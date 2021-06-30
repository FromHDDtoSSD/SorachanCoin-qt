
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

    typedef CPubKey::ecmult::secp256k1_gai gai_t;
    void secp256k1_gai_set_zero(gai_t *gai) {
        CPubKey::ecmult::secp256k1_fe_clear(&gai->re);
        CPubKey::ecmult::secp256k1_fe_clear(&gai->im);
        gai->line = 0;
    }
    void secp256k1_gai_set_rezero(gai_t *gai) {
        CPubKey::ecmult::secp256k1_fe_set_int(&gai->re, 0);
    }
    void secp256k1_gai_set_imzero(gai_t *gai) {
        CPubKey::ecmult::secp256k1_fe_set_int(&gai->im, 0);
    }
    gai_t secp256k1_gai_add(const gai_t *gai1, const gai_t *gai2) { // gai1 + gai2
        gai_t gai = *gai1;
        CPubKey::ecmult::secp256k1_fe_add(&gai.re, &gai2->re);
        CPubKey::ecmult::secp256k1_fe_add(&gai.im, &gai2->im);
        return gai;
    }
    gai_t secp256k1_gai_sub(const gai_t *gai1, const gai_t *gai2) { // gai1 - gai2
        gai_t gai = *gai1;
        gai_t _gai2 = *gai2;
        CPubKey::ecmult::secp256k1_fe_mul_int(&_gai2.re, -1);
        CPubKey::ecmult::secp256k1_fe_mul_int(&_gai2.im, -1);
        CPubKey::ecmult::secp256k1_fe_add(&gai.re, &_gai2.re);
        CPubKey::ecmult::secp256k1_fe_add(&gai.im, &_gai2.im);
        return gai;
    }
    gai_t secp256k1_gai_mul(const gai_t *gai1, const gai_t *gai2) { // gai1 * gai2
        gai_t gai;
        secp256k1_gai_set_zero(&gai);

        CPubKey::ecmult::secp256k1_fe re1, re2;
        CPubKey::ecmult::secp256k1_fe_clear(&re1);
        CPubKey::ecmult::secp256k1_fe_clear(&re2);
        CPubKey::ecmult::secp256k1_fe_mul(&re1, &gai1->re, &gai2->re);
        CPubKey::ecmult::secp256k1_fe_mul(&re2, &gai1->im, &gai2->im);
        CPubKey::ecmult::secp256k1_fe_mul_int(&re2, -1);
        CPubKey::ecmult::secp256k1_fe_add(&gai.re, &re1);
        CPubKey::ecmult::secp256k1_fe_add(&gai.re, &re2);

        CPubKey::ecmult::secp256k1_fe im1, im2;
        CPubKey::ecmult::secp256k1_fe_clear(&im1);
        CPubKey::ecmult::secp256k1_fe_clear(&im2);
        CPubKey::ecmult::secp256k1_fe_mul(&im1, &gai1->re, &gai2->im);
        CPubKey::ecmult::secp256k1_fe_mul(&im2, &gai1->im, &gai2->re);
        CPubKey::ecmult::secp256k1_fe_add(&gai.im, &im1);
        CPubKey::ecmult::secp256k1_fe_add(&gai.im, &im2);

        return gai;
    }
    gai_t secp256k1_gai_div(const gai_t *gai1, const gai_t *gai2) { // gai1 / gai2
        CPubKey::ecmult::secp256k1_fe gai2re_sqr, gai2im_sqr, gai2_div, gai2_inv;
        CPubKey::ecmult::secp256k1_fe_clear(&gai2re_sqr);
        CPubKey::ecmult::secp256k1_fe_clear(&gai2im_sqr);
        CPubKey::ecmult::secp256k1_fe_clear(&gai2_div);
        CPubKey::ecmult::secp256k1_fe_clear(&gai2_inv);
        CPubKey::ecmult::secp256k1_fe_sqr(&gai2re_sqr, &gai2->re);
        CPubKey::ecmult::secp256k1_fe_sqr(&gai2im_sqr, &gai2->im);
        CPubKey::ecmult::secp256k1_fe_add(&gai2_div, &gai2re_sqr);
        CPubKey::ecmult::secp256k1_fe_add(&gai2_div, &gai2im_sqr);
        CPubKey::ecmult::secp256k1_fe_inv(&gai2_inv, &gai2_div);

        CPubKey::ecmult::secp256k1_fe gai_re2;
        CPubKey::ecmult::secp256k1_fe gai_im2;
        CPubKey::ecmult::secp256k1_fe_clear(&gai_re2);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_im2);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_re2, &gai1->re, &gai2->re);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_im2, &gai1->im, &gai2->im);

        CPubKey::ecmult::secp256k1_fe gai_reim_negate;
        CPubKey::ecmult::secp256k1_fe gai_reim;
        CPubKey::ecmult::secp256k1_fe_clear(&gai_reim_negate);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_reim);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_reim_negate, &gai1->re, &gai2->im);
        CPubKey::ecmult::secp256k1_fe_mul_int(&gai_reim_negate, -1);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_reim, &gai2->re, &gai1->im);

        gai_t gai;
        secp256k1_gai_set_zero(&gai);

        CPubKey::ecmult::secp256k1_fe gai_re_result;
        CPubKey::ecmult::secp256k1_fe_clear(&gai_re_result);
        CPubKey::ecmult::secp256k1_fe_add(&gai_re_result, &gai_re2);
        CPubKey::ecmult::secp256k1_fe_add(&gai_re_result, &gai_im2);
        CPubKey::ecmult::secp256k1_fe_mul(&gai.re, &gai_re_result, &gai2_inv);

        CPubKey::ecmult::secp256k1_fe gai_im_result;
        CPubKey::ecmult::secp256k1_fe_clear(&gai_im_result);
        CPubKey::ecmult::secp256k1_fe_add(&gai_im_result, &gai_reim_negate);
        CPubKey::ecmult::secp256k1_fe_add(&gai_im_result, &gai_reim);
        CPubKey::ecmult::secp256k1_fe_mul(&gai.im, &gai_im_result, &gai2_inv);

        return gai;
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
