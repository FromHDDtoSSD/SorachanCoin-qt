
#include <bignum.h>
#include <uint256.h>

class uint256_bignum_test {
public:
    uint256_bignum_test() {
        debugcs::instance() << "bignum(uint256b) test" << debugcs::endl();
        CBigNum bNum;  bNum.SetCompact(123456789);
        uint256b uNum; uNum.SetCompact(123456789);
        debugcs::instance() << "CBigNum GetCompact: " << bNum.GetCompact() << debugcs::endl();
        debugcs::instance() << "uint256b GetCompact: " << uNum.GetCompact() << debugcs::endl();
        assert(bNum.GetCompact()==uNum.GetCompact());
    }
};
#ifdef DEBUG
uint256_bignum_test bnum_test;
#endif
