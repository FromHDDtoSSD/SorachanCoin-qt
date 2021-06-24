
#include <key/privkey.h>
#include <key/pubkey.h>
#include <debugcs/debugcs.h>

class key_test {
public:
    key_test() {
        debugcs::instance() << "key_test" << debugcs::endl();

    }
};
#ifdef DEBUG
key_test key_test_obj;
#endif
