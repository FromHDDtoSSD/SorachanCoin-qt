
#include <bignum.h>
#include <uint256.h>
#include <script/scriptnum.h>
#include <debugcs/debugcs.h>

class bignum_test {
public:
    bignum_test() {
        debugcs::instance() << "bignum_test" << debugcs::endl();

        // https://www.iuec.co.jp/blockchain/bignum.html
        CBigNum bNum(123456789);
        uint256b uNum(123456789);
        debugcs::instance() << "CBigNum GetCompact: " << bNum.GetCompact() << debugcs::endl();
        debugcs::instance() << "uint256b GetCompact: " << uNum.GetCompact() << debugcs::endl();
        assert(bNum.GetCompact()==uNum.GetCompact());

        CBigNum bnTarget1(123456789);
        uint256 u256Target1(123456789);
        assert(bnTarget1.getuint256()==u256Target1);

        bignum_vector vch;
        for (int i=1; i<33; ++i)
            vch.push_back((uint8_t)i);
        assert(vch.size()==sizeof(uint256));
        CBigNum bnTarget2(vch);
        uint256 u256Target2(vch);
        assert(bnTarget2.getuint256()==u256Target2);

        bnTarget2 -= bnTarget1;
        u256Target2 -= u256Target1;
        assert(bnTarget2.getuint256()==u256Target2);

        assert(~bnTarget2.getuint256()==~u256Target2);

        bnTarget2 >>= 136;
        u256Target2 >>= 136;
        assert(bnTarget2.getuint256()==u256Target2);

        assert(bnTarget2.getuint64()==u256Target2.GetLow64());
        assert(bnTarget2.getuint<uint32_t>()==(u256Target2.GetLow64() & ((~uint64_t(0))>>32)));

        uint256b u256Target3(u256Target2);
        assert(bnTarget2.GetCompact()==u256Target3.GetCompact());
    }
};
#ifdef DEBUG
bignum_test bignum_test_obj;
#endif
