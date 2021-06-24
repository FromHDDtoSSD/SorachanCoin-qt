
#include <script/script.h>
#include <debugcs/debugcs.h>

class script_test {
public:
    script_test() {
        debugcs::instance() << "script_test" << debugcs::endl();

    }
};
#ifdef DEBUG
script_test script_test_obj;
#endif
