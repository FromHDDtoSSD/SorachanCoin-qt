
#include <string>
#include <serialize.h>

class CSerDebug {
public:
    CSerDebug() {
        flags = 0;
    }

    CSerDebug(const std::string &str1In, const std::string &str2In, const std::string &str3In) {
        str1 = str1In;
        str2 = str2In;
        str3 = str3In;
        flags = 0;
    }

    void insertflags(int flagsIn) {
        flags = flagsIn;
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action) {
        if(ser_action.ForRead()) {
            if(flags == 0) {
                READWRITE(str1);
                READWRITE(str2);
                READWRITE(str3);
                assert(s.size() == 0);
            } else if (flags == 1) {
                READWRITE(str1);
                assert(s.size() > 0);
            }
        } else {
            if(flags == 0) {
                assert(s.size() == 0);
                READWRITE(str1);
                READWRITE(str2);
                READWRITE(str3);
            } else if (flags == 1) {
                assert(s.size() == 0);
                READWRITE(str1);
                READWRITE(str2);
            }
        }
    }

    std::string ToString() const {
        std::string ret;
        if(str1.size() > 0)
            ret += str1;
        if(str2.size() > 0)
            ret += str2;
        if(str3.size() > 0)
            ret += str3;
        return ret;
    }

private:
    std::string str1, str2, str3;
    int flags;
};

void Debug_checking_sign_verify() {
    std::string str1 = "SorachanCoin";
    std::string str2 = "SorachanCoin 2";
    std::string str3 = "SorachanCoin 3";
    CSerDebug obj1(str1, str2, str3);
    CDataStream stream;
    stream << obj1;

    CSerDebug obj2;
    obj2.insertflags(1);
    stream >> obj2;

    debugcs::instance() << obj2.ToString().c_str() << debugcs::endl();
}

void Debug_checking_sign_verify2() {}
