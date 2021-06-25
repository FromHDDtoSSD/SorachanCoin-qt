
#include <key/privkey.h>
#include <key/pubkey.h>
#include <debugcs/debugcs.h>
#include <util.h>

class key_test {
public:
    static std::string ToString(const CPubKey::secp256k1_unit &obj) {
        const char *p = (const char *)&obj.d[0];
        std::string str;
        for(int i=0; i<32; ++i) {
            char tmp[32];
            ::sprintf(tmp, "0x%X ", (int)p[i] & 0xFF);
            str += tmp;
        }
        return str;
    }
    key_test() {
        debugcs::instance() << "key_test" << debugcs::endl();

        CPubKey::secp256k1_unit r, s;
        int overflow=0;
        int ret=1;
        std::vector<unsigned char> vchRS;
        vchRS.reserve(64);
        for(int i=0; i<64; ++i)
            vchRS.push_back(0xFF);
        CPubKey::secp256k1_scalar_set_be32(&r, &vchRS[0], &overflow);
        ret &= !overflow;
        CPubKey::secp256k1_scalar_set_be32(&s, &vchRS[32], &overflow);
        ret &= !overflow;

        ::fprintf(stdout, "r: %s\ns: %s\n", ToString(r).c_str(), ToString(s).c_str());

        CPubKey::secp256k1_ecdsa_recoverable_signature ers;
        CPubKey::secp256k1_ecdsa_recoverable_signature_save(&ers, &r, &s, 0);

        util::Sleep(10000);
    }
};
#ifdef DEBUG
key_test key_test_obj;
#endif
