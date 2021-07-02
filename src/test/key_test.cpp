
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

    //
    // secp256k1_fe sub, div
    //
    // Note: if use modifier[], must use primary conversion: normalize fe_operator modifier[]
    // e.g.1: (fe1 + fe2) * fe3 - fe4 + fe5
    // - operator use negate modifier
    // primary conversion: normalize +fe5 negate[+fe4] *fe3 +fe2 +fe1 0
    //
    // e.g.2: fe1 - fe2 + fe3 (fe1 - fe2 >= fe3)
    // primary conversion: normalize +fe3 negate[+fe2] +fe1 0 or +fe3 normalize negate[+fe2] +fe1 0
    //
    // e.g.3: fe1 - fe2 + fe3 (fe1 - fe2 < fe3)
    // primary conversion: normalize +fe3 negate[+fe2] +fe1 0
    //
    CPubKey::ecmult::secp256k1_fe secp256k1_fe_sub_normalize(const CPubKey::ecmult::secp256k1_fe *fe1, const CPubKey::ecmult::secp256k1_fe *fe2) { // fe1 - fe2 (-fe2 + fe1)
        CPubKey::ecmult::secp256k1_fe fe_na_fe2;
        CPubKey::ecmult::secp256k1_fe_clear(&fe_na_fe2);
        CPubKey::ecmult::secp256k1_fe_negate(&fe_na_fe2, fe2, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_na_fe2, fe1);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_na_fe2);
        return fe_na_fe2;
    }
    CPubKey::ecmult::secp256k1_fe secp256k1_fe_sub(const CPubKey::ecmult::secp256k1_fe *fe1, const CPubKey::ecmult::secp256k1_fe *fe2) { // negate[+fe2] + fe1
        CPubKey::ecmult::secp256k1_fe fe_na_fe2;
        CPubKey::ecmult::secp256k1_fe_clear(&fe_na_fe2);
        CPubKey::ecmult::secp256k1_fe_negate(&fe_na_fe2, fe2, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_na_fe2, fe1);
        return fe_na_fe2;
    }
    CPubKey::ecmult::secp256k1_fe secp256k1_fe_div_normalize(const CPubKey::ecmult::secp256k1_fe *fe1, const CPubKey::ecmult::secp256k1_fe *fe2) { // fe1 / fe2
        CPubKey::ecmult::secp256k1_fe fe_inv_fe2, fe_div;
        CPubKey::ecmult::secp256k1_fe_clear(&fe_inv_fe2);
        CPubKey::ecmult::secp256k1_fe_clear(&fe_div);
        CPubKey::ecmult::secp256k1_fe_inv(&fe_inv_fe2, fe2);
        CPubKey::ecmult::secp256k1_fe_mul(&fe_div, fe1, &fe_inv_fe2);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_div);
        return fe_div;
    }
    CPubKey::ecmult::secp256k1_fe secp256k1_fe_div(const CPubKey::ecmult::secp256k1_fe *fe1, const CPubKey::ecmult::secp256k1_fe *fe2) { // inv[*fe2] * fe1
        CPubKey::ecmult::secp256k1_fe fe_inv_fe2, fe_div;
        CPubKey::ecmult::secp256k1_fe_clear(&fe_inv_fe2);
        CPubKey::ecmult::secp256k1_fe_clear(&fe_div);
        CPubKey::ecmult::secp256k1_fe_inv(&fe_inv_fe2, fe2);
        CPubKey::ecmult::secp256k1_fe_mul(&fe_div, fe1, &fe_inv_fe2);
        return fe_div;
    }
    int secp256k1_fe_get_signed(const CPubKey::ecmult::secp256k1_fe *fe_na) { // negate[+fe_na] -: 0, +: 1
        CPubKey::ecmult::secp256k1_fe fe_check = *fe_na;
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_check);
        return (fe_check.n[9]==0x3FFFFFUL) ? 0: 1;
    }

    // gat_t + - * /
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
    gai_t secp256k1_gai_conj(const gai_t *gai1) { // (gai1)*
        gai_t gai;
        secp256k1_gai_set_zero(&gai);
        CPubKey::ecmult::secp256k1_fe gai_im_negate = gai1->im;
        CPubKey::ecmult::secp256k1_fe_mul_int(&gai_im_negate, -1);
        gai.re = gai1->re;
        gai.im = gai_im_negate;
        return gai;
    }
    int secp256k1_gai_equal(const gai_t *gai1, const gai_t *gai2) { // gai1 == gai2
        int g1 = CPubKey::ecmult::secp256k1_fe_equal(&gai1->re, &gai2->re);
        int g2 = CPubKey::ecmult::secp256k1_fe_equal(&gai1->im, &gai2->im);
        return (g1 && g2) ? 1: 0;
    }

    gai_t secp256k1_gai_dot(const std::pair<gai_t, gai_t> *gaivx, const std::pair<gai_t, gai_t> *gaivy) { // (gaivx, gaivy)
        std::pair<gai_t, gai_t> gaivx_conj;
        gaivx_conj.first = secp256k1_gai_conj(&gaivx->first);
        gaivx_conj.second = secp256k1_gai_conj(&gaivx->second);

        CPubKey::ecmult::secp256k1_fe gai_ae, gai_bf, gai_cg, gai_dh, gai_af, gai_be, gai_ch, gai_dg;
        CPubKey::ecmult::secp256k1_fe_clear(&gai_ae);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_bf);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_cg);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_dh);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_af);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_be);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_ch);
        CPubKey::ecmult::secp256k1_fe_clear(&gai_dg);

        CPubKey::ecmult::secp256k1_fe_mul(&gai_ae, &gaivx_conj.first.re, &gaivy->first.re);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_bf, &gaivx_conj.first.im, &gaivy->first.im);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_cg, &gaivx_conj.second.re, &gaivy->second.re);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_dh, &gaivx_conj.second.im, &gaivy->second.im);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_af, &gaivx_conj.first.re, &gaivy->first.im);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_be, &gaivx_conj.first.im, &gaivy->first.re);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_ch, &gaivx_conj.second.re, &gaivy->second.im);
        CPubKey::ecmult::secp256k1_fe_mul(&gai_dg, &gaivx_conj.second.im, &gaivy->second.re);

        gai_t gai_dot;
        secp256k1_gai_set_zero(&gai_dot);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.re, &gai_ae);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.re, &gai_bf);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.re, &gai_cg);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.re, &gai_dh);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.im, &gai_af);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.im, &gai_be);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.im, &gai_ch);
        CPubKey::ecmult::secp256k1_fe_add(&gai_dot.im, &gai_dg);

        return gai_dot;
    }

    // from secp256k1_scalar to uint256
    uint256 secp256k1_scalar_get_uint256(const CPubKey::secp256k1_unit *unit) {
        uint256 value;
        CPubKey::secp256k1_scalar_get_be32((unsigned char *)&value, unit);
        return value;
    }
    std::pair<uint256, uint256> secp256k1_scalar_get_uint256(const CPubKey::secp256k1_unit *re, const CPubKey::secp256k1_unit *im) {
        return std::make_pair(secp256k1_scalar_get_uint256(re), secp256k1_scalar_get_uint256(im));
    }
    std::pair<uint256, uint256> secp256k1_scalar_get_uint256(const gai_t *gai) {
        int overflow = 0;
        CPubKey::secp256k1_unit unit_re, unit_im;
        CPubKey::secp256k1_scalar_set_int(&unit_re, 0);
        CPubKey::secp256k1_scalar_set_int(&unit_im, 0);
        CPubKey::secp256k1_scalar_set_be32(&unit_re, (const unsigned char *)&gai->re, &overflow);
        CPubKey::secp256k1_scalar_set_be32(&unit_im, (const unsigned char *)&gai->im, &overflow);
        return secp256k1_scalar_get_uint256(&unit_re, &unit_im);
    }

    // from secp256k1_fe to std::string
    std::string secp256k1_fe_ToString(const CPubKey::ecmult::secp256k1_fe *fe) {
        CPubKey::secp256k1_unit unit;
        int overflow = 0;
        CPubKey::secp256k1_scalar_set_be32(&unit, (const unsigned char *)fe, &overflow);
        uint256 value;
        if(! overflow)
            CPubKey::secp256k1_scalar_get_be32((unsigned char *)&value, &unit);
        else
            value = ~uint256(0);
        return tfm::format("0x%s", value.ToString().c_str());
    }

    // from gai_t to std::string
    std::string secp256k1_gai_ToString(const gai_t *gai) {
        std::pair<uint256, uint256> gai_reim = secp256k1_scalar_get_uint256(gai);
        if(gai_reim.first!=0 && gai_reim.second!=0)
            return tfm::format("secp256k1 gai\n Re: %s0x%s\n Im: %s0x%s\n", gai->re_negate?"-":"", gai_reim.first.ToString().c_str(), gai->im_negate?"-":"", gai_reim.second.ToString().c_str());
        else if(gai_reim.second==0) // im == 0
            return tfm::format("secp256k1 gai\n Re: %s0x%s\n Im: zero\n", gai->re_negate?"-":"", gai_reim.first.ToString().c_str());
        else // re == 0
            return tfm::format("secp256k1 gai\n Re: zero\n Im: %s0x%s\n", gai->im_negate?"-":"", gai_reim.second.ToString().c_str());
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

        CPubKey::ecmult::secp256k1_gai gai_z1x, gai_z1y, gai_z2x, gai_z2y;
        secp256k1_gai_set_zero(&gai_z1x);
        secp256k1_gai_set_zero(&gai_z1y);
        secp256k1_gai_set_zero(&gai_z2x);
        secp256k1_gai_set_zero(&gai_z2y);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z1x.re, 1);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z1x.im, 2);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z1y.re, 3);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z1y.im, 4);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z2x.re, 5);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z2x.im, 6);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z2y.re, 7);
        CPubKey::ecmult::secp256k1_fe_set_int(&gai_z2y.im, 8);
        //auto gaivx = std::make_pair(gai_z1x, gai_z1y);
        //auto gaivy = std::make_pair(gai_z2x, gai_z2y);

        CPubKey::ecmult::secp256k1_fe fe_test1, fe_test2, fe_na;
        CPubKey::ecmult::secp256k1_fe_clear(&fe_test1);
        CPubKey::ecmult::secp256k1_fe_clear(&fe_test2);
        CPubKey::ecmult::secp256k1_fe_clear(&fe_na);
        CPubKey::ecmult::secp256k1_fe_set_int(&fe_test1, 1234562);
        CPubKey::ecmult::secp256k1_fe_set_int(&fe_test2, 1234567);
        CPubKey::ecmult::secp256k1_fe_negate(&fe_na, &fe_test1, 1);
        CPubKey::ecmult::secp256k1_fe_add(&fe_na, &fe_test2);
        int sign = secp256k1_fe_get_signed(&fe_na);
        ::fprintf(stdout, "sign: %d\n", sign);
        if(sign) {
            CPubKey::ecmult::secp256k1_fe_normalize(&fe_na);
            std::string result = secp256k1_fe_ToString(&fe_na);
            ::fprintf(stdout, "secp256k1_fe value: %s\n", result.c_str());
        } else {

        }

        assert(!"secp256k1 test");
    }
};
#ifdef DEBUG
key_test key_test_obj;
#endif
