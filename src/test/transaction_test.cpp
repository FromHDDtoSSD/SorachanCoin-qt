
#include <block/transaction.h>
#include <block/witness.h>
#include <debugcs/debugcs.h>

class transaction_test {
public:
    transaction_test() {
        debugcs::instance() << "transaction_test" << debugcs::endl();
    }
};
#ifdef DEBUG
transaction_test transaction_test_obj;
#endif
