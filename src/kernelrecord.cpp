
#include "kernelrecord.h"

#include "wallet.h"
#include "base58.h"

bool KernelRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase()) {
        if (wtx.GetDepthInMainChain() < 2) {
            return false;
        }
    }
    if(! wtx.IsTrusted()) {
        return false;
    }
    return true;
}

std::vector<KernelRecord> KernelRecord::decomposeOutput(const CWallet *wallet, const CWalletTx &wtx)
{
    std::vector<KernelRecord> parts;

    int64_t nTime = wtx.GetTxTime();
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;
    int64_t nDayWeight = (std::min((bitsystem::GetAdjustedTime() - nTime), (int64_t)(block_check::nStakeMaxAge + block_check::nStakeMinAge)) - block_check::nStakeMinAge); // DayWeight * 86400

    if (KernelRecord::showTransaction(wtx)) {
        for (unsigned int nOut = 0; nOut < wtx.vout.size(); ++nOut)
        {
            CTxOut txOut = wtx.vout[nOut];
            if( wallet->IsMine(txOut) ) {
                CTxDestination address;
                std::string addrStr;
                uint64_t coinAge = std::max( (txOut.nValue * nDayWeight) / (util::COIN * util::nOneDay), (int64_t)0 );

                if (Script_util::ExtractDestination(txOut.scriptPubKey, address)) {
                    // Sent to Bitcoin Address
                    addrStr = CBitcoinAddress(address).ToString();
                } else {
                    // Sent to IP, or other non-address transaction like OP_EVAL
                    addrStr = mapValue["to"];
                }
                parts.push_back( KernelRecord(hash, nTime, addrStr, txOut.nValue, wtx.IsSpent(nOut), coinAge) );
            }
        }
    }
    return parts;
}

std::string KernelRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}

int64_t KernelRecord::getAge() const
{
    return (bitsystem::GetAdjustedTime() - nTime) / util::nOneDay;
}

uint64_t KernelRecord::getCoinDay() const
{
    int64_t nWeight = bitsystem::GetAdjustedTime() - nTime - block_check::nStakeMinAge;
    if( nWeight <  0) {
        return 0;
    } else {
        nWeight = std::min(nWeight, (int64_t)block_check::nStakeMaxAge);
        uint64_t coinAge = (nValue * nWeight) / (util::COIN * util::nOneDay);
        return coinAge;
    }
}

int64_t KernelRecord::getPoSReward(int nBits, int minutes)
{
    int64_t nWeight = bitsystem::GetAdjustedTime() - nTime + minutes * 60;
    if(nWeight < block_check::nStakeMinAge) {
        return 0;
    } else {
        uint64_t coinAge = (nValue * nWeight) / (util::COIN * util::nOneDay);
        return diff::reward::GetProofOfStakeReward(coinAge, nBits, bitsystem::GetAdjustedTime() + minutes * 60);
    }
}

double KernelRecord::getProbToMintStake(double difficulty, int timeOffset) const
{
    int64_t Weight = std::min((bitsystem::GetAdjustedTime() - nTime) + timeOffset, (int64_t)(block_check::nStakeMinAge + block_check::nStakeMaxAge)) - block_check::nStakeMinAge;
    uint64_t coinAge = std::max(nValue * Weight / (util::COIN * util::nOneDay), (int64_t)0);
    double sp = pow(static_cast<double>(2), 40) * difficulty; // old 48
    return (double)coinAge / sp;
}

double KernelRecord::getProbToMintWithinNMinutes(double difficulty, int minutes)
{
    auto getPowStake = [] (const KernelRecord *obj, double difficulty, int timeOffset, int second, double &prob) {
        double p = pow(1 - obj->getProbToMintStake(difficulty, timeOffset), second);
        prob *= p;
    };

    if(difficulty != prevDifficulty || minutes != prevMinutes) {
        double prob = 1;
        int d = minutes / (60 * 24); // Number of full days
        int m = minutes % (60 * 24); // Number of minutes in the last day

        // Probabilities for the first d days
        for(int i=0; i < d; ++i)
        {
            int timeOffset = i * util::nOneDay;
            getPowStake(this, difficulty, timeOffset, util::nOneDay, prob);
        }

        // Probability for the m minutes of the last day
        int timeOffset = d * util::nOneDay;
        getPowStake(this, difficulty, timeOffset, 60 * m, prob);

        prob = 1 - prob;

        prevProbability = prob;
        prevDifficulty = difficulty;
        prevMinutes = minutes;
    }
    return prevProbability;
}
