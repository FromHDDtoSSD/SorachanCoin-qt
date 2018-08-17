// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include <algorithm>

#include "timestamps.h"
#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"
#include "scrypt.h"

#include "checkqueue.h"

#include <limits>
#include <list>
#include <map>

class CWallet;
class CBlock;
class CBlockIndex;
class CBlockLocator;
class CKeyItem;
class CReserveKey;
class COutPoint;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;
class CTxDB;

class CReserveKey;
class CTxIndex;
class CScriptCheck;

//
// block_param
//
namespace block_param
{
	const unsigned int MAX_BLOCK_SIZE = 1000000;
	const unsigned int MAX_BLOCK_SIZE_GEN = MAX_BLOCK_SIZE / 2;
	const unsigned int MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;

	const unsigned int MAX_ORPHAN_TRANSACTIONS = MAX_BLOCK_SIZE / 100;	// allow orphan block size
	const unsigned int MAX_INV_SZ = 50000;

	const int64_t COIN_YEAR_REWARD = 3 * util::CENT;
	const int64_t MAX_MINT_PROOF_OF_WORK = 10 * util::COIN;				// find new block 10 coin PoW

	const int64_t MIN_TX_FEE = 10000;
	const int64_t MIN_RELAY_TX_FEE = MIN_TX_FEE;
	const int64_t MAX_MONEY = 8000000 * util::COIN;
	const int64_t MIN_TXOUT_AMOUNT = util::CENT / 100;

	const unsigned int LOCKTIME_THRESHOLD = 500000000;					// Threshold for nLockTime: below this value it is interpreted as block number, otherwise as UNIX timestamp. Tue Nov  5 00:53:20 1985 UTC
	const int MAX_SCRIPTCHECK_THREADS = 16;								// Maximum number of script-checking threads allowed

	const int64_t COIN_PREMINE = 860000 * util::COIN;

	//
	// Genesis
	//
    const char *const pszTimestamp = "SorachanCoin ... www.junkhdd.com 06-Aug-2018 10:00:00 UTC";
    const uint32_t nGenesisTimeMainnet = timestamps::GENESIS_TIME_STAMP;
    const uint32_t nGenesisTimeTestnet = timestamps::GENESIS_TIME_STAMP;

    const uint32_t nGenesisNonceMainnet = 1181853;
    const uint32_t nGenesisNonceTestnet = 51764;

    const uint256 hashMerkleRoot("0x56eaf6327efb5ce6ece504d585e7f802f0ed5f65b6b262350ee530e2894dce84");
    const uint256 hashGenesisBlock("0x0000030d0ed5a5492e703714059aead5e3800d02de651c1f4079b8d55e6963c7");
    const uint256 hashGenesisBlockTestNet("0x00002f6601da66030580c89a4652b44cf330102c42e2b4e06d97958df7738478");
}

//
// PoW / PoS difficulty
//
namespace diff
{
	namespace testnet
	{
		const CBigNum bnProofOfWorkLimit(~uint256(0) >> 16);				// 16 bits PoW target limit for testnet
	}
	namespace mainnet
	{
		const CBigNum bnProofOfWorkLimit(~uint256(0) >> 20);				// "standard" scrypt target limit for proof of work, results with 0.000244140625 proof of work difficulty
	}
    extern CBigNum bnProofOfWorkLimit;// = mainnet::bnProofOfWorkLimit;

	const CBigNum bnProofOfStakeLimit(~uint256(0) >> 27);					// 0.03125  proof of stake difficulty
	const uint256 nPoWBase = uint256("0x00000000ffff0000000000000000000000000000000000000000000000000000"); // difficulty-1 target

	// minimum amount of work that could possibly be required nTime after
	class amount : private no_instance
	{
	private:
		static unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime);
		static CBigNum GetProofOfStakeLimit(int nHeight, unsigned int nTime);
	public:
		static unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);
		static unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime);
	};

	// check range and proof-of matches claimed amount
	class check : private no_instance
	{
	public:
		static bool CheckProofOfWork(uint256 hash, unsigned int nBits);
	};

	//  miner's coin reward based on nBits
	class reward : private no_instance
	{
	public:
		static int64_t GetProofOfWorkReward(unsigned int nBits, int64_t nFees = 0);
		static int64_t GetProofOfStakeReward(int64_t nCoinAge, unsigned int nBits, int64_t nTime, bool bCoinYearOnly = false);
		//static int64_t GetProofOfBenchmarkReward(unsigned int nBits, int64_t nFees = 0);
	};

	// get proof of work blocks max spacing according to hard-coded conditions
	class spacing : private no_instance
	{
	private:
		static int64_t GetTargetSpacingWorkMax(int nHeight, unsigned int nTime);
	public:
		static const CBlockIndex *GetLastBlockIndex(const CBlockIndex *pindex, bool fProofOfStake);
		static unsigned int GetNextTargetRequired(const CBlockIndex *pindexLast, bool fProofOfStake);
	};
}

//
// block_process
//
namespace block_process
{
    extern CCriticalSection cs_main;								// LOCK(block_process::cs_main)

    extern std::map<uint256, CBlock *> mapOrphanBlocks;
    extern std::map<uint256, uint256> mapProofOfStake;

	class manage : private no_instance
	{
	private:
		static std::multimap<uint256, CBlock *> mapOrphanBlocksByPrev;
		static std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan;
		static std::map<uint256, CTransaction> mapOrphanTransactions;
		static std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev;
		static CMedianFilter<int> cPeerBlockCounts;					// Amount of blocks that other nodes claim to have

		static uint256 GetOrphanRoot(const CBlock *pblock);			// Work back to the first block in the orphan chain
		static bool ReserealizeBlockSignature(CBlock *pblock);
		static bool IsCanonicalBlockSignature(CBlock *pblock);
		static bool ProcessMessage(CNode *pfrom, std::string strCommand, CDataStream &vRecv);
		static bool AlreadyHave(CTxDB &txdb, const CInv &inv);
		static void Inventory(const uint256 &hash);
		static bool AddOrphanTx(const CTransaction &tx);
		static void EraseOrphanTx(uint256 hash);
		static unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);
	public:
		static int64_t nPingInterval;

		static uint256 WantedByOrphan(const CBlock *pblockOrphan);	// Work back to the first block in the orphan chain
		static bool IsInitialBlockDownload();
		static void ResendWalletTransactions(bool fForceResend = false);
		static bool ProcessBlock(CNode *pfrom, CBlock *pblock);
		static bool ProcessMessages(CNode *pfrom);
		static bool SendMessages(CNode *pto);

		static int GetNumBlocksOfPeers();
	};
}

//
// block_alert
//
namespace block_alert
{
	class manage : private no_instance
	{
	public:
		static std::string GetWarnings(std::string strFor);
	};
}

//
// block_check 1
// block_check 2 is under "class CScriptCheck" define(main.h).
//
namespace block_check
{
	namespace testnet
	{
		const unsigned int nStakeMinAge = 2 * util::nOneHour;		// test net min age is 2 hours
        const unsigned int nModifierInterval = 3 * 60;				// test modifier interval is 3 minutes
        const unsigned int nStakeTargetSpacing = 1 * 60;			// test block spacing is 1 minutes
        const unsigned int nPowTargetSpacing = 60;
	}
	namespace mainnet
	{
		const unsigned int nStakeMinAge = 8 * util::nOneHour;
        const unsigned int nModifierInterval = 10 * 60;             // main modifier 10 minutes
        const unsigned int nStakeTargetSpacing = 6 * 60;
        const unsigned int nPowTargetSpacing = 3 * 60;
	}

    extern unsigned int nStakeMinAge;// = mainnet::nStakeMinAge;
	const unsigned int nStakeMaxAge = 90 * util::nOneDay;

    extern unsigned int nStakeTargetSpacing;// = mainnet::nStakeTargetSpacing;
    extern unsigned int nPowTargetSpacing; // = mainnet::nPowTargetSpacing;
    extern unsigned int nModifierInterval;// = mainnet::nModifierInterval;
	const int64_t nTargetTimespan = 7 * util::nOneDay;

	class manage : private no_instance
	{
	public:
		static void InvalidChainFound(CBlockIndex *pindexNew);
		static bool VerifySignature(const CTransaction &txFrom, const CTransaction &txTo, unsigned int nIn, unsigned int flags, int nHashType);

		static bool Reorganize(CTxDB &txdb, CBlockIndex *pindexNew);

		static int64_t PastDrift(int64_t nTime) {	// up to 2 hours from the past
			return nTime - 2 * util::nOneHour;
		}
		static int64_t FutureDrift(int64_t nTime) { // up to 2 hours from the future
			return nTime + 2 * util::nOneHour;
		}
	};
}

//
// block_load
//
namespace block_load
{
	void UnloadBlockIndex();
	bool LoadBlockIndex(bool fAllowNew=true);	// start

	bool LoadExternalBlockFile(FILE *fileIn);	// bootstrap
}

//
// block_transaction
//
namespace block_transaction
{
	const unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS = 36;
	const unsigned int DONOT_ACCEPT_BLOCKS_ADMIT_HOURS_TESTNET = 168;

	const unsigned int MAX_ORPHAN_SERIALIZESIZE = 5000;	// send-big-orphans memory exhaustion attack. 10,000 orphans, each of which is at most 5,000 bytes big is at most 500 megabytes of orphans

	namespace testnet
	{
		const int nCoinbaseMaturity = 6;
	}
	namespace mainnet
	{
		const int nCoinbaseMaturity = 15;
	}
    extern int nCoinbaseMaturity;// = mainnet::nCoinbaseMaturity;

	class manage : private no_instance
	{
	private:
		static CBlockIndex *pblockindexFBBHLast;

	public:
        static void setnull_pblockindexFBBHLast() { pblockindexFBBHLast = NULL; }	// New Block

		static bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
		static CBlockIndex *FindBlockByHeight(int nHeight);

		static bool MoneyRange(int64_t nValue) { 
			return (nValue >= 0 && nValue <= block_param::MAX_MONEY); 
		}
	};
}

//
// block_notify
//
class block_notify : private no_instance
{
	friend class CBlock;
private:
	static void SetBestChain(const CBlockLocator &loc);
	static void UpdatedTransaction(const uint256 &hashTx);
	static void PrintWallets(const CBlock &block);
};

//
// wallet_process
//
namespace wallet_process
{
	class manage : private no_instance
	{
	private:
		static CCriticalSection cs_setpwalletRegistered;
	public:
		static void RegisterWallet(CWallet *pwalletIn);
		static void UnregisterWallet(CWallet *pwalletIn);
		static void SyncWithWallets(const CTransaction &tx, const CBlock *pblock = NULL, bool fUpdate = false, bool fConnect = true);
	};
}

//
// file_open
//
class file_open : private no_instance
{
private:
	static const uint64_t nMinDiskSpace;	// Minimum disk space required - used in CheckDiskSpace() 52428800(currently 50MB)

public:
	static FILE *OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char *pszMode="rb");
	static bool CheckDiskSpace(uint64_t nAdditionalBytes=0);
	static FILE *AppendBlockFile(unsigned int &nFileRet);
};

//
// block_info 1
// block_info 2 is util.h
//
namespace block_info
{
    extern CScript COINBASE_FLAGS;

    extern std::map<uint256, CBlockIndex *> mapBlockIndex;		// Hash Tree (CBlockIndex is node.)
    extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
    extern CBlockIndex *pindexGenesisBlock;// = NULL;

	const std::string strMessageMagic = coin_param::strCoinName + " Signed Message:\n";

    extern int64_t nTimeBestReceived;// = 0;
    extern std::set<CWallet *> setpwalletRegistered;

    extern uint64_t nLastBlockTx;// = 0;
    extern uint64_t nLastBlockSize;// = 0;
    extern uint32_t nLastCoinStakeSearchInterval;// = 0;

    extern int nBestHeight;// = -1;
    extern uint256 nBestChainTrust;// = 0;
    extern uint256 nBestInvalidTrust;// = 0;
    extern uint256 hashBestChain;// = 0;
    extern CBlockIndex *pindexBest;// = NULL;
    extern unsigned int nTransactionsUpdated;// = 0;

	// Settings
    extern int64_t nTransactionFee;// = block_param::MIN_TX_FEE;
    extern int64_t nMinimumInputValue;// = block_param::MIN_TXOUT_AMOUNT;
    extern int nScriptCheckThreads;// = 0;
}

//
// Position on disk for a particular transaction
//
class CDiskTxPos
{
//private:
	// CDiskTxPos(const CDiskTxPos &); // {}
	// CDiskTxPos &operator=(const CDiskTxPos &); // {}

public:
	uint32_t nFile;
	uint32_t nBlockPos;
	uint32_t nTxPos;

	CDiskTxPos() {
		SetNull();
	}

	CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn) {
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nTxPos = nTxPosIn;
	}

	void SetNull() { 
        nFile = std::numeric_limits<uint32_t>::max();
        nBlockPos = 0;
        nTxPos = 0;
	}

	bool IsNull() const { 
        return (nFile == std::numeric_limits<uint32_t>::max());
	}

	friend bool operator==(const CDiskTxPos &a, const CDiskTxPos &b) {
		return (a.nFile     == b.nFile &&
				a.nBlockPos == b.nBlockPos &&
				a.nTxPos    == b.nTxPos);
	}

	friend bool operator!=(const CDiskTxPos &a, const CDiskTxPos &b) {
		return !(a == b);
	}

	std::string ToString() const {
		if (IsNull()) {
			return "null";
		} else {
			return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
		}
	}

	void print() const {
		printf("%s", ToString().c_str());
	}

	IMPLEMENT_SERIALIZE(
		READWRITE(FLATDATA(*this));
	)
};

//
// An inpoint - a combination of a transaction and an index n into its vin
//
class CInPoint
{
private:
	CInPoint(const CInPoint &); // {}
	// CInPoint &operator=(const CInPoint &); // {}

public:
	CTransaction* ptx;
	uint32_t n;

	CInPoint() { 
		SetNull();
	}

	CInPoint(CTransaction *ptxIn, unsigned int nIn) {
        ptx = ptxIn;
        n = nIn;
	}

	void SetNull() { 
        ptx = NULL;
        n = std::numeric_limits<uint32_t>::max();
	}

	bool IsNull() const {
        return (ptx == NULL && n == std::numeric_limits<uint32_t>::max());
	}
};

//
// An outpoint - a combination of a transaction hash and an index n into its vout
//
class COutPoint
{
//private:
	// COutPoint(const COutPoint &); // {}
	// COutPoint &operator=(const COutPoint &); // {}

public:
	uint256 hash;
	uint32_t n;

	COutPoint() {
		SetNull();
	}
    
	COutPoint(uint256 hashIn, unsigned int nIn) { 
        hash = hashIn;
        n = nIn;
	}

	void SetNull() { 
        hash = 0;
        n = std::numeric_limits<uint32_t>::max();
	}

	bool IsNull() const { 
        return (hash == 0 && n == std::numeric_limits<uint32_t>::max());
	}

	friend bool operator<(const COutPoint &a, const COutPoint &b) {
		return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
	}

	friend bool operator==(const COutPoint &a, const COutPoint &b) {
		return (a.hash == b.hash && a.n == b.n);
	}

	friend bool operator!=(const COutPoint &a, const COutPoint &b) {
		return !(a == b);
	}

	std::string ToString() const {
        return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10).c_str(), n);
	}

	void print() const {
		printf("%s\n", ToString().c_str());
	}

	IMPLEMENT_SERIALIZE( 
		READWRITE(FLATDATA(*this));
	)
};

//
// CTransaction IN
// An input of a transaction.  It contains the location of the previous
// transaction's output that it claims and a signature that matches the output's public key.
//
class CTxIn
{
//private:
	// CTxIn(const CTxIn &); // {}
	// CTxIn &operator=(const CTxIn &); // {}

public:
	COutPoint prevout;
	CScript scriptSig;
	uint32_t nSequence;

	CTxIn() {
        nSequence = std::numeric_limits<unsigned int>::max();
	}

	explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
        prevout = prevoutIn;
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
	}

	CTxIn(uint256 hashPrevTx, unsigned int nOut, CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max()) {
        prevout = COutPoint(hashPrevTx, nOut);
        scriptSig = scriptSigIn;
        nSequence = nSequenceIn;
	}

	IMPLEMENT_SERIALIZE
	(
		READWRITE(this->prevout);
		READWRITE(this->scriptSig);
		READWRITE(this->nSequence);
	)

	bool IsFinal() const {
        return (nSequence == std::numeric_limits<unsigned int>::max());
	}

	friend bool operator==(const CTxIn &a, const CTxIn &b) {
		return (a.prevout   == b.prevout &&
				a.scriptSig == b.scriptSig &&
				a.nSequence == b.nSequence);
	}

	friend bool operator!=(const CTxIn &a, const CTxIn &b) {
		return !(a == b);
	}

	std::string ToStringShort() const {
		return strprintf(" %s %d", prevout.hash.ToString().c_str(), prevout.n);
	}

	std::string ToString() const {
		std::string str;
		str += "CTxIn(";
		str += prevout.ToString();
		if (prevout.IsNull()) {
			str += strprintf(", coinbase %s", util::HexStr(scriptSig).c_str());
		} else {
			str += strprintf(", scriptSig=%s", scriptSig.ToString().substr(0,24).c_str());
		}
		if (nSequence != std::numeric_limits<unsigned int>::max()) {
			str += strprintf(", nSequence=%u", nSequence);
		}
		str += ")";
		return str;
	}

	void print() const {
		printf("%s\n", ToString().c_str());
	}
};

//
// CTransaction OUT
// An output of a transaction. It contains the public key that the next input must be able to sign with to claim it.
//
class CTxOut
{
//private:
	// CTxOut(const CTxOut &); // {}
	// CTxOut &operator=(const CTxOut &); // {}

public:
	int64_t nValue;
	CScript scriptPubKey;

	CTxOut() {
		SetNull();
	}

	CTxOut(int64_t nValueIn, CScript scriptPubKeyIn) {
        nValue = nValueIn;
        scriptPubKey = scriptPubKeyIn;
	}

	IMPLEMENT_SERIALIZE
	(
		READWRITE(this->nValue);
		READWRITE(this->scriptPubKey);
	)

	void SetNull() {
        nValue = -1;
        scriptPubKey.clear();
	}

	bool IsNull() {
		return (this->nValue == -1);
	}

	void SetEmpty() {
        nValue = 0;
        scriptPubKey.clear();
	}

	bool IsEmpty() const {
        return (nValue == 0 && scriptPubKey.empty());
	}

	uint256 GetHash() const {
		return hash_basis::SerializeHash(*this);
	}

	friend bool operator==(const CTxOut& a, const CTxOut& b) {
		return (a.nValue       == b.nValue &&
				a.scriptPubKey == b.scriptPubKey);
	}

	friend bool operator!=(const CTxOut& a, const CTxOut& b) {
		return !(a == b);
	}

	std::string ToStringShort() const {
        return strprintf(" out %s %s", bitstr::FormatMoney(nValue).c_str(), scriptPubKey.ToString(true).c_str());
	}

	std::string ToString() const {
		if (IsEmpty()) {
			return "CTxOut(empty)";
		}
        if (scriptPubKey.size() < 6) {
			return "CTxOut(error)";
		}
        return strprintf("CTxOut(nValue=%s, scriptPubKey=%s)", bitstr::FormatMoney(nValue).c_str(), scriptPubKey.ToString().c_str());
	}

	void print() const {
		printf("%s\n", ToString().c_str());
	}
};

//
// The basic transaction that is broadcasted on the network and contained in blocks.  A transaction can contain multiple inputs and outputs.
//
typedef std::map<uint256, std::pair<CTxIndex, CTransaction> > MapPrevTx;
class CTransaction
{
//private:
	// CTransaction(const CTransaction &); // {}
	// CTransaction &operator=(const CTransaction &); // {}

public:
	enum GetMinFee_mode
	{
		GMF_BLOCK,
		GMF_RELAY,
		GMF_SEND
	};

public:
	static const int CURRENT_VERSION = 1;

	int nVersion;
	uint32_t nTime;
	std::vector<CTxIn> vin;
	std::vector<CTxOut> vout;
	uint32_t nLockTime;

	//
	// Denial-of-service detection:
	//
	mutable int nDoS;
	bool DoS(int nDoSIn, bool fIn) const { 
        nDoS += nDoSIn;
		return fIn; 
	}

	CTransaction() {
		SetNull();
	}
	virtual ~CTransaction() {}

	IMPLEMENT_SERIALIZE
	(
		READWRITE(this->nVersion);
		nVersion = this->nVersion;
		READWRITE(this->nTime);
		READWRITE(this->vin);
		READWRITE(this->vout);
		READWRITE(this->nLockTime);
	)

	void SetNull() {
        nVersion = CTransaction::CURRENT_VERSION;
        nTime = (uint32_t)bitsystem::GetAdjustedTime();
        vin.clear();
        vout.clear();
        nLockTime = 0;
        nDoS = 0;  // Denial-of-service prevention
	}

	bool IsNull() const {
        return (vin.empty() && vout.empty());
	}

	uint256 GetHash() const {
		return hash_basis::SerializeHash(*this);
	}

	bool IsFinal(int nBlockHeight = 0, int64_t nBlockTime = 0) const {
		//
		// Time based nLockTime implemented in 0.1.6
		//
        if (nLockTime == 0) {
			return true;
		}
		if (nBlockHeight == 0) {
			nBlockHeight = block_info::nBestHeight;
		}
		if (nBlockTime == 0) {
			nBlockTime = bitsystem::GetAdjustedTime();
		}
        if ((int64_t)nLockTime < ((int64_t)nLockTime < block_param::LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime)) {
			return true;
		}
        BOOST_FOREACH(const CTxIn &txin, this->vin)
		{
			if (! txin.IsFinal()) {
				return false;
			}
		}
		return true;
	}

	bool IsNewerThan(const CTransaction &old) const {
        if (vin.size() != old.vin.size()) {
			return false;
		}

		for (unsigned int i = 0; i < vin.size(); ++i)
		{
            if (vin[i].prevout != old.vin[i].prevout) {
				return false;
			}
		}

		bool fNewer = false;
		unsigned int nLowest = std::numeric_limits<unsigned int>::max();
		for (unsigned int i = 0; i < vin.size(); ++i)
		{
			if (vin[i].nSequence != old.vin[i].nSequence) {
				if (vin[i].nSequence <= nLowest) {
					fNewer = false;
					nLowest = vin[i].nSequence;
				}
				if (old.vin[i].nSequence < nLowest) {
					fNewer = true;
					nLowest = old.vin[i].nSequence;
				}
			}
		}
		return fNewer;
	}

	bool IsCoinBase() const {
        return (vin.size() == 1 && vin[0].prevout.IsNull() && vout.size() >= 1);
	}

	bool IsCoinStake() const {
		//
		// ppcoin: the coin stake transaction is marked with the first output empty
		//
        return (vin.size() > 0 && (!vin[0].prevout.IsNull()) && vout.size() >= 2 && vout[0].IsEmpty());
	}

	//
	// Check for standard transaction types
	// @return True if all outputs (scriptPubKeys) use only standard transaction forms
	//
	bool IsStandard(std::string &strReason) const;
	bool IsStandard() const {
		std::string strReason;
		return IsStandard(strReason);
	}

	//
	// Check for standard transaction types
	//	@param[in] mapInputs	Map of previous transactions that have outputs we're spending
	//	@return True if all inputs (scriptSigs) use only standard transaction forms
	//	@see CTransaction::FetchInputs
	//
	bool AreInputsStandard(const MapPrevTx &mapInputs) const;

	//
	// Count ECDSA signature operations the old-fashioned (pre-0.6) way
	//	@return number of sigops this transaction's outputs will produce when spent
	//	@see CTransaction::FetchInputs
	//
	unsigned int GetLegacySigOpCount() const;

	//
	// Count ECDSA signature operations in pay-to-script-hash inputs.
	//	@param[in] mapInputs	Map of previous transactions that have outputs we're spending
	//	@return maximum number of sigops required to validate this transaction's inputs
	//	@see CTransaction::FetchInputs
	//
	unsigned int GetP2SHSigOpCount(const MapPrevTx &mapInputs) const;

	//
	// Amount of bitcoins spent by this transaction.
	//	@return sum of all outputs (note: does not include fees)
	//
	int64_t GetValueOut() const {
		int64_t nValueOut = 0;
		BOOST_FOREACH(const CTxOut &txout, vout)
		{
			nValueOut += txout.nValue;
			if (!block_transaction::manage::MoneyRange(txout.nValue) || !block_transaction::manage::MoneyRange(nValueOut)) {
				throw std::runtime_error("CTransaction::GetValueOut() : value out of range");
			}
		}
		return nValueOut;
	}

	//
	// Amount of bitcoins coming in to this transaction
	//	Note that lightweight clients may not know anything besides the hash of previous transactions,
	//	so may not be able to calculate this.
	//	@param[in] mapInputs	Map of previous transactions that have outputs we're spending
	//	@return	Sum of value of all inputs (scriptSigs)
	//	@see CTransaction::FetchInputs
	//
	int64_t GetValueIn(const MapPrevTx &mapInputs) const;

	static bool AllowFree(double dPriority) {
		//
		// Large (in bytes) low-priority (new, small-coin) transactions need a fee.
		//
		return dPriority > util::COIN * 960 / 250;
	}
	int64_t GetMinFee(unsigned int nBlockSize=1, bool fAllowFree=false, enum GetMinFee_mode mode=GMF_BLOCK, unsigned int nBytes = 0) const;

	bool ReadFromDisk(CDiskTxPos pos, FILE **pfileRet=NULL) {
		CAutoFile filein = CAutoFile(file_open::OpenBlockFile(pos.nFile, 0, pfileRet ? "rb+" : "rb"), SER_DISK, version::CLIENT_VERSION);
		if (! filein) {
			return print::error("CTransaction::ReadFromDisk() : file_open::OpenBlockFile failed");
		}

		// Read transaction
		if (fseek(filein, pos.nTxPos, SEEK_SET) != 0) {
			return print::error("CTransaction::ReadFromDisk() : fseek failed");
		}

		try {
			filein >> *this;
		} catch (const std::exception &) {
			return print::error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
		}

		// Return file pointer
		if (pfileRet) {
			if (::fseek(filein, pos.nTxPos, SEEK_SET) != 0) {
				return print::error("CTransaction::ReadFromDisk() : second fseek failed");
			}
			*pfileRet = filein.release();
		}
		return true;
	}

	friend bool operator==(const CTransaction &a, const CTransaction &b) {
		return (a.nVersion  == b.nVersion &&
				a.nTime     == b.nTime &&
				a.vin       == b.vin &&
				a.vout      == b.vout &&
				a.nLockTime == b.nLockTime);
	}

	friend bool operator!=(const CTransaction &a, const CTransaction &b) {
		return !(a == b);
	}

	std::string ToStringShort() const {
		std::string str;
		str += strprintf("%s %s", GetHash().ToString().c_str(), IsCoinBase()? "base" : (IsCoinStake()? "stake" : "user"));
		return str;
	}

	std::string ToString() const {
		std::string str;
		str += IsCoinBase() ? "Coinbase" : (IsCoinStake() ? "Coinstake" : "CTransaction");
		str += strprintf("(hash=%s, nTime=%d, ver=%d, vin.size=%" PRIszu ", vout.size=%" PRIszu ", nLockTime=%d)\n",
			GetHash().ToString().substr(0,10).c_str(),
            nTime,
            nVersion,
            vin.size(),
            vout.size(),
            nLockTime);

		for (unsigned int i = 0; i < vin.size(); ++i)
		{
            str += "    " + vin[i].ToString() + "\n";
		}
		for (unsigned int i = 0; i < vout.size(); ++i)
		{
            str += "    " + vout[i].ToString() + "\n";
		}

		return str;
	}

	void print() const {
		printf("%s", ToString().c_str());
	}

	bool ReadFromDisk(CTxDB &txdb, COutPoint prevout, CTxIndex &txindexRet);
	bool ReadFromDisk(CTxDB &txdb, COutPoint prevout);
	bool ReadFromDisk(COutPoint prevout);
	bool DisconnectInputs(CTxDB &txdb);

	/** Fetch from memory and/or disk. inputsRet keys are transaction hashes.

	 @param[in] txdb	Transaction database
	 @param[in] mapTestPool	List of pending changes to the transaction index database
	 @param[in] fBlock	True if being called to add a new best-block to the chain
	 @param[in] fMiner	True if being called by miner::CreateNewBlock
	 @param[out] inputsRet	Pointers to this transaction's inputs
	 @param[out] fInvalid	returns true if transaction is invalid
	 @return	Returns true if all inputs are in txdb or mapTestPool
	 */
	bool FetchInputs(CTxDB &txdb, const std::map<uint256, CTxIndex> &mapTestPool, bool fBlock, bool fMiner, MapPrevTx &inputsRet, bool &fInvalid);

	/** Sanity check previous transactions, then, if all checks succeed,
		mark them as spent by this transaction.

		@param[in] inputs	Previous transactions (from FetchInputs)
		@param[out] mapTestPool	Keeps track of inputs that need to be updated on disk
		@param[in] posThisTx	Position of this transaction on disk
		@param[in] pindexBlock
		@param[in] fBlock	true if called from ConnectBlock
		@param[in] fMiner	true if called from miner::CreateNewBlock
		@param[in] fScriptChecks	enable scripts validation?
		@param[in] flags	Script_param::STRICT_FLAGS script validation flags
		@param[in] pvChecks	NULL If pvChecks is not NULL, script checks are pushed onto it instead of being performed inline.
		@return Returns true if all checks succeed
	 */
	bool ConnectInputs(CTxDB &txdb, MapPrevTx inputs, std::map<uint256, CTxIndex> &mapTestPool, const CDiskTxPos &posThisTx, const CBlockIndex *pindexBlock, bool fBlock, bool fMiner, bool fScriptChecks=true, unsigned int flags=Script_param::STRICT_FLAGS, std::vector<CScriptCheck> *pvChecks = NULL);

	bool ClientConnectInputs();
	bool CheckTransaction() const;
	bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs=true, bool *pfMissingInputs=NULL);
	bool GetCoinAge(CTxDB &txdb, uint64_t &nCoinAge) const;  // ppcoin: get transaction coin age

protected:
	const CTxOut &GetOutputFor(const CTxIn &input, const MapPrevTx &inputs) const;
};

//
// Closure representing one script verification
// Note that this stores references to the spending transaction
//
class CScriptCheck
{
private:
	// CScriptCheck(const CScriptCheck &); // {}
	CScriptCheck &operator=(const CScriptCheck &); // {}

	CScript scriptPubKey;
	const CTransaction *ptxTo;
	unsigned int nIn;
	unsigned int nFlags;
	int nHashType;

public:
	CScriptCheck() {}
	CScriptCheck(const CTransaction& txFromIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, int nHashTypeIn) :
	scriptPubKey(txFromIn.vout[txToIn.vin[nInIn].prevout.n].scriptPubKey), ptxTo(&txToIn), nIn(nInIn), nFlags(nFlagsIn), nHashType(nHashTypeIn) {}

	bool operator()() const;

	void swap(CScriptCheck &check) {
        scriptPubKey.swap(check.scriptPubKey);
        std::swap(ptxTo, check.ptxTo);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(nHashType, check.nHashType);
	}
};

//
// block_check 2
//
namespace block_check
{
	class thread : private no_instance
	{
	public:
		static CCheckQueue<CScriptCheck> scriptcheckqueue;

		static void ThreadScriptCheck(void *);
		static void ThreadScriptCheckQuit();
	};
}

//
// A transaction with a merkle branch linking it to the block chain.
//
class CMerkleTx : public CTransaction
{
//private:
	// CMerkleTx(const CMerkleTx &); // {}
	// CMerkleTx &operator=(const CMerkleTx &); // {}

public:
	uint256 hashBlock;
	std::vector<uint256> vMerkleBranch;
	int32_t nIndex;

	//
	// memory only
	//
	mutable bool fMerkleVerified;

	CMerkleTx() {
		Init();
	}

	CMerkleTx(const CTransaction& txIn) : CTransaction(txIn) {
		Init();
	}

	void Init() {
        hashBlock = 0;
        nIndex = -1;
        fMerkleVerified = false;
	}

	IMPLEMENT_SERIALIZE
	(
		nSerSize += imp_ser::manage::SerReadWrite(s, *(CTransaction *)this, nType, nVersion, ser_action);
		nVersion = this->nVersion;
		READWRITE(this->hashBlock);
		READWRITE(this->vMerkleBranch);
		READWRITE(this->nIndex);
	)

	int SetMerkleBranch(const CBlock *pblock=NULL);
	int GetDepthInMainChain(CBlockIndex *&pindexRet) const;
	int GetDepthInMainChain() const {
		CBlockIndex *pindexRet; 
		return GetDepthInMainChain(pindexRet);
	}

	bool IsInMainChain() const { 
		return GetDepthInMainChain() > 0;
	}

	int GetBlocksToMaturity() const;
	bool AcceptToMemoryPool(CTxDB &txdb, bool fCheckInputs=true);
	bool AcceptToMemoryPool();
};

//
// A txdb record that contains the disk location of a transaction and the locations of transactions that spend its outputs. 
// vSpent is really only used as a flag, but having the location is very helpful for debugging.
//
class CTxIndex
{
//private:
	// CTxIndex(const CTxIndex &); // {}
	// CTxIndex &operator=(const CTxIndex &); // {}
public:
	CDiskTxPos pos;
	std::vector<CDiskTxPos> vSpent;

	CTxIndex() {
		SetNull();
	}

	CTxIndex(const CDiskTxPos& posIn, unsigned int nOutputs) {
        pos = posIn;
        vSpent.resize(nOutputs);
	}

	IMPLEMENT_SERIALIZE
	(
		if (!(nType & SER_GETHASH)) {
			READWRITE(nVersion);
		}

		READWRITE(this->pos);
		READWRITE(this->vSpent);
	)

	void SetNull() {
		pos.SetNull();
		vSpent.clear();
	}

	bool IsNull() {
		return pos.IsNull();
	}

	friend bool operator==(const CTxIndex &a, const CTxIndex &b) {
		return (a.pos    == b.pos &&
				a.vSpent == b.vSpent);
	}

	friend bool operator!=(const CTxIndex &a, const CTxIndex &b) {
		return !(a == b);
	}

	int GetDepthInMainChain() const;
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator of the block.
 *
 * Blocks are appended to blk0001.dat files on disk. Their location on disk is indexed by CBlockIndex objects in memory.
 */
class CBlock
{
//private:
	// CBlock(const CBlock &); // {}
	// CBlock &operator=(const CBlock &); // {}

public:
	static void PrintBlockTree();

public:
	// header
	static const int CURRENT_VERSION = 6;

	int32_t nVersion;
	uint256 hashPrevBlock;
	uint256 hashMerkleRoot;
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;

	// network and disk
	std::vector<CTransaction> vtx;

	// ppcoin: block signature - signed by one of the coin base txout[N]'s owner
	std::vector<unsigned char> vchBlockSig;

	// memory only
	mutable std::vector<uint256> vMerkleTree;

	// Denial-of-service detection:
	mutable int nDoS;
	bool DoS(int nDoSIn, bool fIn) const {
		nDoS += nDoSIn;
		return fIn;
	}

	CBlock() {
		SetNull();
	}

	void SetNull() {
        nVersion = CBlock::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        vtx.clear();
        vchBlockSig.clear();
        vMerkleTree.clear();
        nDoS = 0;
	}

	bool IsNull() const {
        return (nBits == 0);
	}

	uint256 GetHash() const {
		return bitscrypt::scrypt_blockhash((const uint8_t *)&nVersion);
	}

	int64_t GetBlockTime() const {
        return (int64_t)nTime;
	}

	void UpdateTime(const CBlockIndex *pindexPrev);

	//
	// entropy bit for stake modifier if chosen by modifier
	//
	unsigned int GetStakeEntropyBit(unsigned int nHeight) const {
		//
		// Take last bit of block hash as entropy bit
		//
		unsigned int nEntropyBit = ((GetHash().Get64()) & 1llu);
        if (args_bool::fDebug && map_arg::GetBoolArg("-printstakemodifier")) {
			printf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetHash().ToString().c_str(), nEntropyBit);
		}
		return nEntropyBit;
	}

	//
	// ppcoin: two types of block: proof-of-work or proof-of-stake
	//
	bool IsProofOfStake() const {
        return (vtx.size() > 1 && vtx[1].IsCoinStake());
	}
	bool IsProofOfWork() const {
		return !IsProofOfStake();
	}
	std::pair<COutPoint, unsigned int> GetProofOfStake() const {
        return IsProofOfStake() ? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
	}

	//
	// ppcoin: get max transaction timestamp
	//
	int64_t GetMaxTransactionTime() const {
		int64_t maxTransactionTime = 0;
        BOOST_FOREACH(const CTransaction &tx, vtx)
		{
			maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
		}
		return maxTransactionTime;
	}

	//
	// Memory all load, Create Hash Tree
	//
	uint256 BuildMerkleTree() const {
        vMerkleTree.clear();
		BOOST_FOREACH(const CTransaction &tx, this->vtx)
		{
            vMerkleTree.push_back(tx.GetHash());
		}

		int j = 0;
		for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
		{
			for (int i = 0; i < nSize; i += 2)
			{
				int i2 = std::min(i + 1, nSize - 1);
                vMerkleTree.push_back(hash_basis::Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                                       BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
			}
			j += nSize;
		}
        return (vMerkleTree.empty() ? 0 : vMerkleTree.back());
	}
	std::vector<uint256> GetMerkleBranch(int nIndex) const {
        if (vMerkleTree.empty()) {
			BuildMerkleTree();
		}

		std::vector<uint256> vMerkleBranch;
		int j = 0;
		for (int nSize = (int)vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
		{
			int i = std::min(nIndex ^ 1, nSize - 1);
			vMerkleBranch.push_back(vMerkleTree[j+i]);
			nIndex >>= 1;
			j += nSize;
		}
		return vMerkleBranch;
	}

	static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256> &vMerkleBranch, int nIndex) {
		if (nIndex == -1) {
			return 0;
		}

		BOOST_FOREACH(const uint256 &otherside, vMerkleBranch)
		{
			if (nIndex & 1) {
				hash = hash_basis::Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
			} else {
				hash = hash_basis::Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
			}
			nIndex >>= 1;
		}
		return hash;
	}

	bool WriteToDisk(unsigned int &nFileRet, unsigned int &nBlockPosRet) {
		//
		// Open history file to append
		//
		CAutoFile fileout = CAutoFile(file_open::AppendBlockFile(nFileRet), SER_DISK, version::CLIENT_VERSION);
		if (! fileout) {
			return print::error("CBlock::WriteToDisk() : file_open::AppendBlockFile failed");
		}

		// Write index header
		unsigned int nSize = fileout.GetSerializeSize(*this);
		fileout << FLATDATA(block_info::gpchMessageStart) << nSize;

		// Write block
		long fileOutPos = ::ftell(fileout);
		if (fileOutPos < 0) {
			return print::error("CBlock::WriteToDisk() : ftell failed");
		}
		nBlockPosRet = fileOutPos;
		fileout << *this;

		//
		// Flush stdio buffers and commit to disk before returning
		//
		fflush(fileout);
		if (!block_process::manage::IsInitialBlockDownload() || (block_info::nBestHeight + 1) % 500 == 0) {
			iofs::FileCommit(fileout);
		}

		return true;
	}

	bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true) {
		SetNull();

		// Open history file to read
		CAutoFile filein = CAutoFile(file_open::OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, version::CLIENT_VERSION);
		if (! filein) {
			return print::error("CBlock::ReadFromDisk() : file_open::OpenBlockFile failed");
		}
		if (! fReadTransactions) {
			filein.AddType(SER_BLOCKHEADERONLY);
		}

		// Read block
		try {
			filein >> *this;
		} catch (const std::exception &) {
			return print::error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
		}

		// Check the header
		if (fReadTransactions && IsProofOfWork() && !diff::check::CheckProofOfWork(GetHash(), nBits)) {
			return print::error("CBlock::ReadFromDisk() : errors in block header");
		}

		return true;
	}

	void print() const {
		printf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu ", vchBlockSig=%s)\n",
			GetHash().ToString().c_str(),
            nVersion,
			hashPrevBlock.ToString().c_str(),
			hashMerkleRoot.ToString().c_str(),
            nTime, nBits, nNonce,
			vtx.size(),
            util::HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
		for (unsigned int i = 0; i < this->vtx.size(); ++i)
		{
			printf("  ");
            vtx[i].print();
		}

		printf("  vMerkleTree: ");
		for (unsigned int i = 0; i < vMerkleTree.size(); ++i)
		{
			printf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
		}
		printf("\n");
	}

	bool DisconnectBlock(CTxDB &txdb, CBlockIndex *pindex);
	bool ConnectBlock(CTxDB &txdb, CBlockIndex *pindex, bool fJustCheck=false);
	bool ReadFromDisk(const CBlockIndex *pindex, bool fReadTransactions=true);
	bool SetBestChain(CTxDB &txdb, CBlockIndex *pindexNew);
	bool AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos);
	bool CheckBlock(bool fCheckPOW=true, bool fCheckMerkleRoot=true, bool fCheckSig=true) const;
	bool AcceptBlock();
	bool GetCoinAge(uint64_t &nCoinAge) const; // ppcoin: calculate total coin age spent in block
	bool CheckBlockSignature() const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);		// CBlock my Version READWRITE
        nVersion = this->nVersion;
        READWRITE(this->hashPrevBlock);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);

        // ConnectBlock depends on vtx following header to generate CDiskTxPos
        if (!(nType & (SER_GETHASH|SER_BLOCKHEADERONLY))) {
            READWRITE(this->vtx);
            READWRITE(this->vchBlockSig);
        } else if (fRead) {
            const_cast<CBlock *>(this)->vtx.clear();
            const_cast<CBlock *>(this)->vchBlockSig.clear();
        }
    )

private:
	bool SetBestChainInner(CTxDB &txdb, CBlockIndex *pindexNew);
};

//
// Block Node Class
//
/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block.  pprev and pnext link a path through the
 * main/longest chain.  A blockindex may have multiple pprev pointing back
 * to it, but pnext will only point forward to the longest branch, or will
 * be null if the block is not part of the longest chain.
 */
class CBlockIndex
{
private:
	// CBlockIndex(const CBlockIndex &); // {}
	CBlockIndex &operator=(const CBlockIndex &); // {}

public:
	const uint256 *phashBlock;
	CBlockIndex *pprev;
	CBlockIndex *pnext;

	uint32_t nFile;
	uint32_t nBlockPos;
	uint256 nChainTrust; // ppcoin: trust score of block chain
	int32_t nHeight;

	int64_t nMint;
	int64_t nMoneySupply;

	uint32_t nFlags;  // ppcoin: block index flags
	enum  
	{
		BLOCK_PROOF_OF_STAKE = (1 << 0),		// is proof-of-stake block
		BLOCK_STAKE_ENTROPY  = (1 << 1),		// entropy bit for stake modifier
		BLOCK_STAKE_MODIFIER = (1 << 2),		// regenerated stake modifier
	};

	uint64_t nStakeModifier; // hash modifier for proof-of-stake
	uint32_t nStakeModifierChecksum; // checksum of index; in-memeory only

	// proof-of-stake specific fields
	COutPoint prevoutStake;
	uint32_t nStakeTime;
	uint256 hashProofOfStake;

	// block header
	int32_t  nVersion;
	uint256  hashMerkleRoot;
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;

	CBlockIndex() {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = 0;
        nBlockPos = 0;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
        prevoutStake.SetNull();
        nStakeTime = 0;

        nVersion       = 0;
        hashMerkleRoot = 0;
        nTime          = 0;
        nBits          = 0;
        nNonce         = 0;
	}

	CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock &block) {
        phashBlock = NULL;
        pprev = NULL;
        pnext = NULL;
        nFile = nFileIn;
        nBlockPos = nBlockPosIn;
        nHeight = 0;
        nChainTrust = 0;
        nMint = 0;
        nMoneySupply = 0;
        nFlags = 0;
        nStakeModifier = 0;
        nStakeModifierChecksum = 0;
        hashProofOfStake = 0;
		if (block.IsProofOfStake()) {
			SetProofOfStake();
            prevoutStake = block.vtx[1].vin[0].prevout;
            nStakeTime = block.vtx[1].nTime;
		} else {
			prevoutStake.SetNull();
			nStakeTime = 0;
		}

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
	}

	virtual ~CBlockIndex() {}

	CBlock GetBlockHeader() const {
		CBlock block;

		block.nVersion       = nVersion;
		if (pprev) {
			block.hashPrevBlock = pprev->GetBlockHash();
		}

		block.hashMerkleRoot = hashMerkleRoot;
		block.nTime          = nTime;
		block.nBits          = nBits;
		block.nNonce         = nNonce;
		return block;
	}

	uint256 GetBlockHash() const {
		return *phashBlock;
	}

	int64_t GetBlockTime() const {
		return (int64_t)nTime;
	}

	uint256 GetBlockTrust() const;

	bool IsInMainChain() const {
        return (pnext || this == block_info::pindexBest);
	}

	bool CheckIndex() const {
		return true;
	}

	const unsigned int nMedianTimeSpan = 11;
	int64_t GetMedianTimePast() const {

		int64_t pmedian[nMedianTimeSpan];

		int64_t *pbegin = &pmedian[nMedianTimeSpan];
		int64_t *pend = &pmedian[nMedianTimeSpan];

		const CBlockIndex *pindex = this;
        for (int i = 0; i < (const int)nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
		{
			*(--pbegin) = pindex->GetBlockTime();
		}

		std::sort(pbegin, pend);
		return pbegin[(pend - pbegin) / 2];
	}
	int64_t GetMedianTime() const {
		const CBlockIndex *pindex = this;
        for (int i = 0; i < (const int)nMedianTimeSpan / 2; i++)
		{
			if (!pindex->pnext)
				return GetBlockTime();
			pindex = pindex->pnext;
		}
		return pindex->GetMedianTimePast();
	}

    //
	// Returns true if there are nRequired or more blocks of minVersion or above
	// in the last nToCheck blocks, starting at pstart and going backwards.
	//
	static bool IsSuperMajority(int minVersion, const CBlockIndex *pstart, unsigned int nRequired, unsigned int nToCheck);

	bool IsProofOfWork() const {
		return !IsProofOfStake();
	}

	bool IsProofOfStake() const {
        return (nFlags & BLOCK_PROOF_OF_STAKE);
	}

	void SetProofOfStake() {
        nFlags |= BLOCK_PROOF_OF_STAKE;
	}

	unsigned int GetStakeEntropyBit() const {
        return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
	}

	bool SetStakeEntropyBit(unsigned int nEntropyBit) {
		if (nEntropyBit > 1) {
			return false;
		}

        nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
		return true;
	}

	bool GeneratedStakeModifier() const {
        return (nFlags & BLOCK_STAKE_MODIFIER) != 0;
	}

	void SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier) {
        nStakeModifier = nModifier;
		if (fGeneratedStakeModifier) {
            nFlags |= BLOCK_STAKE_MODIFIER;
		}
	}

	std::string ToString() const {
		return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nMint=%s, nMoneySupply=%s, \
						  nFlags=(%s)(%d)(%s), \
						  nStakeModifier=%016"PRIx64", nStakeModifierChecksum=%08x, hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
			(const void *)pprev,
			(const void *)pnext,
			nFile,
			nBlockPos,
			nHeight,
			bitstr::FormatMoney(nMint).c_str(),
			bitstr::FormatMoney(nMoneySupply).c_str(),

			GeneratedStakeModifier() ? "MOD": "-",   GetStakeEntropyBit(),   IsProofOfStake() ? "PoS": "PoW",

			nStakeModifier,
			nStakeModifierChecksum,
			hashProofOfStake.ToString().c_str(),
			prevoutStake.ToString().c_str(),
			nStakeTime,
			hashMerkleRoot.ToString().c_str(),
			GetBlockHash().ToString().c_str()
			);
	}

	void print() const {
		printf("%s\n", ToString().c_str());
	}
};

//
// Used to marshal pointers into hashes for db storage.
//
class CDiskBlockIndex : public CBlockIndex
{
private:
	CDiskBlockIndex(const CDiskBlockIndex &); // {}
	CDiskBlockIndex &operator=(const CDiskBlockIndex &); // {}

	mutable uint256 blockHash;

public:
	uint256 hashPrev;
	uint256 hashNext;

	CDiskBlockIndex() {
        hashPrev = 0;
        hashNext = 0;
        blockHash = 0;
	}

	explicit CDiskBlockIndex(CBlockIndex *pindex) : CBlockIndex(*pindex) {
        hashPrev = (pprev ? pprev->GetBlockHash() : 0);
        hashNext = (pnext ? pnext->GetBlockHash() : 0);
	}

	uint256 GetBlockHash() const {
		if (args_bool::fUseFastIndex && (nTime < bitsystem::GetAdjustedTime() - util::nOneDay) && this->blockHash != 0) {
			return blockHash;
		}

		CBlock block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;

		// const_cast<CDiskBlockIndex *>(this)->blockHash = block.GetHash(); // use mutable
        blockHash = block.GetHash();

        return blockHash;
	}

	std::string ToString() const {
		std::string str = "CDiskBlockIndex(";
		str += CBlockIndex::ToString();
		str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)", GetBlockHash().ToString().c_str(), this->hashPrev.ToString().c_str(), this->hashNext.ToString().c_str());
		return str;
	}

	void print() const {
		printf("%s\n", ToString().c_str());
	}

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);	// IMPLEMENT_SERIALIZE has argument(nVersion).
        }

        READWRITE(this->hashNext);
        READWRITE(this->nFile);
        READWRITE(this->nBlockPos);
        READWRITE(this->nHeight);
        READWRITE(this->nMint);
        READWRITE(this->nMoneySupply);
        READWRITE(this->nFlags);
        READWRITE(this->nStakeModifier);
        if (IsProofOfStake()) {
            READWRITE(this->prevoutStake);
            READWRITE(this->nStakeTime);
            READWRITE(this->hashProofOfStake);
        } else if (fRead) {
            const_cast<CDiskBlockIndex *>(this)->prevoutStake.SetNull();
            const_cast<CDiskBlockIndex *>(this)->nStakeTime = 0;
            const_cast<CDiskBlockIndex *>(this)->hashProofOfStake = 0;
        }

        // block header
        READWRITE(this->nVersion);	// CDiskBlockIndex my nVersion
        READWRITE(this->hashPrev);
        READWRITE(this->hashMerkleRoot);
        READWRITE(this->nTime);
        READWRITE(this->nBits);
        READWRITE(this->nNonce);
        READWRITE(this->blockHash);
    )
};

//
// Describes a place in the block chain to another node such that if the
// other node doesn't have the same branch, it can find a recent common trunk.
// The further back it is, the further before the fork it may be.
//
class CBlockLocator
{
private:
	CBlockLocator(const CBlockLocator &); // {}
	CBlockLocator &operator=(const CBlockLocator &); // {}

protected:
	std::vector<uint256> vHave;

public:

	CBlockLocator() {}

	explicit CBlockLocator(const CBlockIndex *pindex) {
		Set(pindex);
	}

	explicit CBlockLocator(uint256 hashBlock) {
		std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hashBlock);
		if (mi != block_info::mapBlockIndex.end()) {
			Set((*mi).second);
		}
	}

	CBlockLocator(const std::vector<uint256> &vHaveIn) {
        vHave = vHaveIn;
	}

	void SetNull() {
        vHave.clear();
	}

	bool IsNull() {
        return vHave.empty();
	}

	void Set(const CBlockIndex *pindex) {
        vHave.clear();
		int nStep = 1;
		while (pindex)
		{
            vHave.push_back(pindex->GetBlockHash());

			//
			// Exponentially larger steps back
			//
			for (int i = 0; pindex && i < nStep; ++i)
			{
				pindex = pindex->pprev;
			}
            if (vHave.size() > 10) {
				nStep *= 2;
			}
		}
        vHave.push_back((!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet));
	}

	int GetDistanceBack() {
		//
		// Retrace how far back it was in the sender's branch
		//
		int nDistance = 0;
		int nStep = 1;
		BOOST_FOREACH(const uint256 &hash, this->vHave)
		{
			std::map<uint256, CBlockIndex *>::iterator mi = block_info::mapBlockIndex.find(hash);
			if (mi != block_info::mapBlockIndex.end()) {
				CBlockIndex *pindex = (*mi).second;
				if (pindex->IsInMainChain()) {
					return nDistance;
				}
			}
			
			nDistance += nStep;
			if (nDistance > 10) {
				nStep *= 2;
			}
		}
		return nDistance;
	}

	CBlockIndex *GetBlockIndex() {
		//
		// Find the first block the caller has in the main chain
		//
		BOOST_FOREACH(const uint256 &hash, this->vHave)
		{
			std::map<uint256, CBlockIndex*>::iterator mi = block_info::mapBlockIndex.find(hash);
			if (mi != block_info::mapBlockIndex.end())
			{
				CBlockIndex *pindex = (*mi).second;
				if (pindex->IsInMainChain()) {
					return pindex;
				}
			}
		}
		return block_info::pindexGenesisBlock;
	}

	uint256 GetBlockHash() {
		//
		// Find the first block the caller has in the main chain
		//
		BOOST_FOREACH(const uint256 &hash, this->vHave)
		{
			std::map<uint256, CBlockIndex*>::iterator mi = block_info::mapBlockIndex.find(hash);
			if (mi != block_info::mapBlockIndex.end()) {
				CBlockIndex *pindex = (*mi).second;
				if (pindex->IsInMainChain()) {
					return hash;
				}
			}
		}
        return (!args_bool::fTestNet ? block_param::hashGenesisBlock : block_param::hashGenesisBlockTestNet);
	}

	int GetHeight() {
		CBlockIndex *pindex = GetBlockIndex();
		if (! pindex) {
			return 0;
		}
		return pindex->nHeight;
	}

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH)) {
            READWRITE(nVersion);	// IMPLEMENT_SERIALIZE has argument(nVersion).
        }

        READWRITE(this->vHave);
    )
};

//
// Transaction Memory Pool
// Singleton Class
//
class CTxMemPool
{
private:
	CTxMemPool() {}

	CTxMemPool(const CTxMemPool &); // {}
	CTxMemPool &operator=(const CTxMemPool &); // {}

public:
	static CTxMemPool mempool;	// instance main.cpp

	mutable CCriticalSection cs;

	std::map<uint256, CTransaction> mapTx;
	std::map<COutPoint, CInPoint> mapNextTx;

	bool accept(CTxDB &txdb, CTransaction &tx, bool fCheckInputs, bool *pfMissingInputs);
	bool addUnchecked(const uint256 &hash, CTransaction &tx);
	bool remove(CTransaction &tx);
	void clear();
	void queryHashes(std::vector<uint256> &vtxid);

	bool IsFromMe(CTransaction &tx);
	void EraseFromWallets(uint256 hash);

	size_t size() {
        LOCK(cs);
        return mapTx.size();
	}

	bool exists(uint256 hash) {
        return (mapTx.count(hash) != 0);
	}

	CTransaction &lookup(uint256 hash) {
        return mapTx[hash];
	}
};

#endif
