// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHECKQUEUE_H
#define CHECKQUEUE_H

#include <algorithm>
#include <vector>
#include <condition_variable>
#include <mutex>
#include <debugcs/debugcs.h>

template<typename T> class CCheckQueueControl;

/** Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */
template<typename T>
class CCheckQueue
{
    CCheckQueue()=delete;
    CCheckQueue(const CCheckQueue &)=delete;
    CCheckQueue(CCheckQueue &&)=delete;
    CCheckQueue &operator=(const CCheckQueue &)=delete;
    CCheckQueue &operator=(CCheckQueue &&)=delete;
private:
    // Mutex to protect the inner state
    mutable std::mutex mutex;

    // Worker threads block on this when out of work
    std::condition_variable condWorker;

    // Master thread blocks on this when out of work
    std::condition_variable condMaster;

    // Quit method blocks on this until all workers are gone
    std::condition_variable condQuit;

    // The queue of elements to be processed.
    // As the order of booleans doesn't matter, it is used as a LIFO (stack)
    std::vector<T> queue;

    // The number of workers (including the master) that are idle.
    int nIdle;

    // The total number of workers (including the master).
    int nTotal;

    // The temporary evaluation result.
    bool fAllOk;

    // Number of verifications that haven't completed yet.
    // This includes elements that are not anymore in queue, but still in
    // worker's own batches.
    unsigned int nTodo;

    // Whether we're shutting down.
    bool fQuit;

    // The maximum number of elements to be processed in one batch
    unsigned int nBatchSize;

    //
    // Internal function that does bulk of the verification work.
    //
    bool Loop(bool fMaster = false) {
        std::condition_variable &cond = fMaster ? this->condMaster : this->condWorker;

        std::vector<T> vChecks;
        vChecks.reserve(this->nBatchSize);

        unsigned int nNow = 0;
        bool fOk = true;
        do
        {
            {
                std::unique_lock<std::mutex> lock(this->mutex);

                // first do the clean-up of the previous loop run (allowing us to do it in the same critsect)
                if (nNow) {
                    this->fAllOk &= fOk;
                    this->nTodo -= nNow;
                    if (this->nTodo == 0 && !fMaster) {
                        // We processed the last element; inform the master he can exit and return the result
                        this->condMaster.notify_one();
                    }
                } else {
                    // first iteration
                    this->nTotal++;
                }

                //
                // logically, the do loop starts here
                //
                while (this->queue.empty())
                {
                    if ((fMaster || this->fQuit) && this->nTodo == 0) {
                        this->nTotal--;
                        if (this->nTotal==0) {
                            this->condQuit.notify_one();
                        }

                        bool fRet = this->fAllOk;
                        // reset the status for new work later
                        if (fMaster) {
                            this->fAllOk = true;
                        }

                        // return the current status
                        return fRet;
                    }
                    this->nIdle++;
                    cond.wait(lock); // wait
                    this->nIdle--;
                }

                //
                // Decide how many work units to process now.
                // * Do not try to do everything at once, but aim for increasingly smaller batches so all workers finish approximately simultaneously.
                // * Try to account for idle jobs which will instantly start helping.
                // * Don't do batches smaller than 1 (duh), or larger than nBatchSize.
                //
                nNow = std::max(1U, std::min(this->nBatchSize, (unsigned int)this->queue.size() / (this->nTotal + this->nIdle + 1)));
                vChecks.resize(nNow);
                for (unsigned int i = 0; i < nNow; ++i)
                {
                     //
                     // We want the lock on the mutex to be as short as possible, so swap jobs from the global
                     // queue to the local batch vector instead of copying.
                     //
                     vChecks[i].swap(queue.back());
                     this->queue.pop_back();
                }

                //
                // Check whether we need to do work at all
                //
                fOk = this->fAllOk;
            } // std::mutex

            //
            // execute work
            //
            for(T &check: vChecks)
            {
                if (fOk) {
                    fOk = check(); // operator()
                }
            }
            vChecks.clear();
        } while(true && !args_bool::fShutdown); // HACK: force queue to shut down
        debugcs::instance() << "checkqueue force shutdown" << debugcs::endl();
        return false;
    }

public:
    // Create a new check queue
    CCheckQueue(unsigned int nBatchSizeIn) : nIdle(0), nTotal(0), fAllOk(true), nTodo(0), fQuit(false), nBatchSize(nBatchSizeIn) {}

    // Worker thread
    void Thread() {
        Loop();
    }

    // Wait until execution finishes, and return whether all evaluations where succesful.
    bool Wait() {
        return Loop(true);
    }

    // Add a batch of checks to the queue
    void __Add(std::vector<T> &vChecks) {
        std::unique_lock<std::mutex> lock(this->mutex);

        for(T &check: vChecks)
        {
            this->queue.push_back(T());
            check.swap(queue.back());
        }
        
        this->nTodo += vChecks.size();
        if (vChecks.size() == 1) {
            this->condWorker.notify_one();
        } else if (vChecks.size() > 1) {
            this->condWorker.notify_all();
        }
    }

    // Add a batch of checks to the queue
    void Add(std::vector<T> &&vChecks) {
        std::unique_lock<std::mutex> lock(this->mutex);

        const size_t size = vChecks.size();
        for(T &check: vChecks) {
            this->queue.emplace_back(std::move(check));
        }
        vChecks.clear();

        this->nTodo += size;
        if (size == 1) {
            this->condWorker.notify_one();
        } else if (size > 1) {
            this->condWorker.notify_all();
        }
    }

    // Shut the queue down
    void Quit(bool fForce=false) {
        std::unique_lock<std::mutex> lock(this->mutex);

        this->fQuit = true;

        //
        // No need to wake the master, as he will quit automatically when all jobs are done.
        //
        debugcs::instance() << "Quit notify_all()" << debugcs::endl();
        this->condWorker.notify_all(); 

        if(fForce==false) {
            while (this->nTotal > 0)
                this->condQuit.wait(lock);
        }
    }

    ~CCheckQueue() {
        debugcs::instance() << "~CCheckQueue()" << debugcs::endl();
        Quit(true);
    }

    bool IsIdle() const {
        std::unique_lock<std::mutex> lock(this->mutex);

        return (this->nTotal == nIdle && this->nTodo == 0 && this->fAllOk == true);
    }
};

/** RAII-style controller object for a CCheckQueue that guarantees the passed
 *  queue is finished before continuing.
 */
template<typename T> class CCheckQueueControl {
    CCheckQueueControl()=delete;
    CCheckQueueControl(const CCheckQueueControl &)=delete;
    CCheckQueueControl(CCheckQueueControl &&)=delete;
    CCheckQueueControl &operator=(const CCheckQueueControl &)=delete;
    CCheckQueueControl &operator=(CCheckQueueControl &&)=delete;

private:
    CCheckQueue<T> *pqueue;
    bool fDone;

public:
    CCheckQueueControl(CCheckQueue<T> *pqueueIn) : pqueue(pqueueIn), fDone(false) {
        // passed queue is supposed to be unused, or NULL
        if (this->pqueue != nullptr) {
            bool isIdle = this->pqueue->IsIdle();
            assert(isIdle);
        }
    }

    bool Wait() {
        if (this->pqueue == nullptr) {
            return true;
        }

        bool fRet = this->pqueue->Wait();
        fDone = true;
        return fRet;
    }

    void __Add(std::vector<T> &vChecks) {
        if (this->pqueue != nullptr) {
            this->pqueue->__Add(vChecks);
        }
    }

    void Add(std::vector<T> &&vChecks) {
        if (this->pqueue != nullptr) {
            this->pqueue->Add(std::move(vChecks));
        }
    }

    ~CCheckQueueControl() {
        if (! this->fDone) {
            Wait();
        }
    }
};

#endif
