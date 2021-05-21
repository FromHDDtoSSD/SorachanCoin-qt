
#include <bignum.h>
#include <uint256.h>

class uint256_bignum_test {
public:
    uint256_bignum_test() {
        debugcs::instance() << "bignum(uint256b) test" << debugcs::endl();
        unsigned char data[] = {'a', 'b', 'c', 'd', 'e', '3', '8', '7'};
        large_uint_vector uvh(BEGIN(data), END(data));
        CBigNum bNum(uvh);
        uint256b uNum(uvh);
        assert(bNum.GetCompact()==uNum.GetCompact());
    }
};
#ifdef DEBUG
//uint256_bignum_test bnum_test;
#endif
