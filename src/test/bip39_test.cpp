
#include <bip32/hdchain.h>
#include <debugcs/debugcs.h>

class bip39_test {
public:
    bip39_test() {
        return; // OK

        debugcs::instance() << "bip39_test" << debugcs::endl();
        debugcs::instance() << bip39_words::generate_mnemonic().ToString() << debugcs::endl();
        debugcs::instance() << bip39_words::generate_priv_mnemonic().ToString() << debugcs::endl();
    }
    ~bip39_test() {}
};
#ifdef DEBUG
//bip39_test bip39_test_obj;
#endif
