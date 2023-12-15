
#include <uint256.h>
#include <bignum.h>
#include <script/scriptnum.h>
#include <debugcs/debugcs.h>

class uintnum_test {
public:
    uintnum_test() {
        debugcs::instance() << "uintnum_test" << debugcs::endl();

        // https://www.iuec.co.jp/blockchain/uint256.html
        uint256 hash = ~uint256(0);
        hash -= uint256(12345678);
        hash -= uint256("0x00002046b1c7938971a6089c7105fc15907b8f27ac8dfea9896c27c593a9a966");
        ::fprintf(stdout, "hash=0x%s\n", hash.ToString().c_str());

        CBigNum bnTarget1(123456789);
        CScriptNum scTarget(123456789);
        assert(bnTarget1.getuint64()==scTarget.getint64());

        CNekoNum nekoTarget(123456789);
        assert(bnTarget1.getuint64()==nekoTarget.getuint64());
    }
};
#ifdef DEBUG
//uintnum_test uintnum_test_obj;
#endif
