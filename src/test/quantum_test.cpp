
#include <quantum/quantum.h>
#include <prevector/prevector.h>
#include <prevector/prevector_s.h>
#include <debugcs/debugcs.h>

class quantum_test {
public:
    quantum_test() {
        debugcs::instance() << "quantum_test" << debugcs::endl();

        // https://www.iuec.co.jp/blockchain/prevector.html
        prevector<28, uint8_t> test;
        test.push_back('n');
        test.push_back('e');
        test.push_back('k');
        test.push_back('o');
        for(auto mi = test.begin(); mi!=test.end(); ++mi)
            ::fprintf(stdout, "%c\n", *mi);
    }
};
#ifdef DEBUG
//quantum_test quantum_test_obj;
#endif
