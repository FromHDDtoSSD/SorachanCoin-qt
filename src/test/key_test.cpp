
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
    static std::string ToString(const CPubKey::ecmult::secp256k1_ge &obj) {
        const uint32_t *x = &obj.x.n[0];
        const uint32_t *y = &obj.y.n[0];
        std::string str = "\nX: ";
        for(int i=0; i<10; ++i) {
            char tmp[32];
            ::sprintf(tmp, "0x%X", x[i]);
            str += tmp;
        }
        str += "\nY: ";
        for(int i=0; i<10; ++i) {
            char tmp[32];
            ::sprintf(tmp, "0x%X", y[i]);
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
        vchRS.reserve(65);
        vchRS.push_back(0x04);
        for(int i=1; i<65; ++i)
            vchRS.push_back(0x10);

        CPubKey::secp256k1_scalar_set_be32(&r, &vchRS[1], &overflow);
        ret &= !overflow;
        CPubKey::secp256k1_scalar_set_be32(&s, &vchRS[33], &overflow);
        ret &= !overflow;

        ::fprintf(stdout, "k1_scalar_set_be32 overflow: %d\n", ret);
        ::fprintf(stdout, "r: %s\ns: %s\n", ToString(r).c_str(), ToString(s).c_str());

        CPubKey::secp256k1_ecdsa_recoverable_signature ers;
        CPubKey::secp256k1_ecdsa_recoverable_signature_save(&ers, &r, &s, 0);

        CPubKey::ecmult::secp256k1_ge Q; // include [x, y] each vector size uint32_t[10] (_fe)
        CPubKey::secp256k1_eckey_pubkey_parse(&Q, &vchRS[0], 65);
        ::fprintf(stdout, "ge: %s\n", ToString(Q).c_str());

        int ret2 = CPubKey::ecmult::secp256k1_ge_is_valid_var(&Q);
        ::fprintf(stdout, "get_is_valid_var: %d\n", ret2);

        util::Sleep(10000);
    }
};
#ifdef DEBUG
key_test key_test_obj;
#endif
