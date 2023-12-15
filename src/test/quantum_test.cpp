
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

        // https://www.iuec.co.jp/blockchain/prevector_s.html
        prevector_s<28, uint8_t> test2; // prevector + ::mlock + ::mprotect
        test2.push_back('h');
        test2.push_back('o');
        test2.push_back('g');
        test2.push_back('o');
        test2.push_back('n');
        test2.push_back('e');
        test2.push_back('k');
        test2.push_back('o');
        for(auto mi = test2.begin(); mi!=test2.end(); ++mi)
            ::fprintf(stdout, "%c\n", *mi);
    }
};
#ifdef DEBUG
//quantum_test quantum_test_obj;
#endif
