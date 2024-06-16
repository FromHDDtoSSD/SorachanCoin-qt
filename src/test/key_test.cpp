
#include <key/privkey.h>
#include <key/pubkey.h>
#include <debugcs/debugcs.h>
#include <util.h>

class key_test {
public:
    static std::string ToString(const CPubKey::secp256k1_scalar &obj) {
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
        gai->re_negate = 0;
        gai->im_negate = 0;
    }
    void secp256k1_gai_set_rezero(gai_t *gai) {
        CPubKey::ecmult::secp256k1_fe_set_int(&gai->re, 0);
        gai->re_negate = 0;
    }
    void secp256k1_gai_set_imzero(gai_t *gai) {
        CPubKey::ecmult::secp256k1_fe_set_int(&gai->im, 0);
        gai->im_negate = 0;
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
    /*
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
    */

    // gai_t init
    gai_t secp256k1_gai_create(int re, int im) {
        gai_t gai;
        secp256k1_gai_set_zero(&gai);
        if(0<=re&&0<=im) {
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.re, re);
            gai.re_negate = 0;
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.im, im);
            gai.im_negate = 0;
        } else if (0>re&&0<=im) {
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.re, (-1)*re);
            gai.re_negate = 1;
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.im, im);
            gai.im_negate = 0;
        } else if (0<=re&&0>im) {
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.re, re);
            gai.re_negate = 0;
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.im, (-1)*im);
            gai.im_negate = 1;
        } else {
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.re, (-1)*re);
            gai.re_negate = 1;
            CPubKey::ecmult::secp256k1_fe_set_int(&gai.im, (-1)*im);
            gai.im_negate = 1;
        }
        return gai;
    }

    // gai_t + - * /
    gai_t secp256k1_gai_add(const gai_t *gai1, const gai_t *gai2) { // gai1 + gai2
        gai_t gai = *gai1;
        gai.re_negate = secp256k1_negate_ope::fe_add_to_negate(&gai.re, gai.re_negate, &gai2->re, gai2->re_negate);
        gai.im_negate = secp256k1_negate_ope::fe_add_to_negate(&gai.im, gai.im_negate, &gai2->im, gai2->im_negate);
        return gai;
    }
    gai_t secp256k1_gai_sub(const gai_t *gai1, const gai_t *gai2) { // gai1 - gai2
        gai_t _gai2 = *gai2;
        _gai2.im_negate = _gai2.im_negate==0? 1: 0;
        _gai2.re_negate = _gai2.re_negate==0? 1: 0;
        return secp256k1_gai_add(gai1, &_gai2);
    }
    gai_t secp256k1_gai_mul(const gai_t *gai1, const gai_t *gai2) { // gai1 * gai2
        CPubKey::ecmult::secp256k1_fe fe_rere = gai1->re;
        int fe_rere_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_rere, gai1->re_negate, &gai2->re, gai2->re_negate);
        CPubKey::ecmult::secp256k1_fe fe_imim = gai1->im;
        int fe_imim_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_imim, gai1->im_negate, &gai2->im, gai2->im_negate);
        CPubKey::ecmult::secp256k1_fe fe_reim12 = gai1->re;
        int fe_reim12_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_reim12, gai1->re_negate, &gai2->im, gai2->im_negate);
        CPubKey::ecmult::secp256k1_fe fe_reim21 = gai1->im;
        int fe_reim21_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_reim21, gai1->im_negate, &gai2->re, gai2->re_negate);

        gai_t gai;
        secp256k1_gai_set_zero(&gai);
        gai.re_negate = secp256k1_negate_ope::fe_add_to_negate(&fe_rere, fe_rere_negate, &fe_imim, fe_imim_negate);
        gai.re = fe_rere;
        gai.im_negate = secp256k1_negate_ope::fe_add_to_negate(&fe_reim12, fe_reim12_negate, &fe_reim21, fe_reim21_negate);
        gai.im = fe_reim12;

        return gai;
    }
    gai_t secp256k1_gai_div(const gai_t *gai1, const gai_t *gai2) { // gai1 / gai2
        CPubKey::ecmult::secp256k1_fe fe_rere = gai1->re;
        int fe_rere_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_rere, gai1->re_negate, &gai2->re, gai2->re_negate);
        CPubKey::ecmult::secp256k1_fe fe_imim = gai1->im;
        int fe_imim_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_imim, gai1->im_negate, &gai2->im, gai2->im_negate);
        CPubKey::ecmult::secp256k1_fe fe_reim12 = gai1->re;
        int fe_reim12_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_reim12, gai1->re_negate, &gai2->im, gai2->im_negate);
        CPubKey::ecmult::secp256k1_fe fe_reim21 = gai1->im;
        int fe_reim21_negate = secp256k1_negate_ope::fe_mul_to_negate(&fe_reim21, gai1->im_negate, &gai2->re, gai2->re_negate);

        CPubKey::ecmult::secp256k1_fe fe_gai2_re2;
        CPubKey::ecmult::secp256k1_fe_mul(&fe_gai2_re2, &gai2->re, &gai2->re);
        CPubKey::ecmult::secp256k1_fe fe_gai2_im2;
        CPubKey::ecmult::secp256k1_fe_mul(&fe_gai2_im2, &gai2->im, &gai2->im);
        CPubKey::ecmult::secp256k1_fe fe_div = fe_gai2_re2;
        CPubKey::ecmult::secp256k1_fe_add(&fe_div, &fe_gai2_im2);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_div);

        gai_t gai;
        secp256k1_gai_set_zero(&gai);
        int gai_re_negate = secp256k1_negate_ope::fe_add_to_negate(&fe_rere, fe_rere_negate, &fe_imim, fe_imim_negate);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_rere);
        gai.re_negate = secp256k1_negate_ope::fe_div_to_negate(&fe_rere, gai_re_negate, &fe_div, 0);
        gai.re = fe_rere;

        int gai_im_negate = secp256k1_negate_ope::fe_sub_to_negate(&fe_reim21, fe_reim21_negate, &fe_reim12, fe_reim12_negate);
        CPubKey::ecmult::secp256k1_fe_normalize(&fe_reim21);
        gai.im_negate = secp256k1_negate_ope::fe_div_to_negate(&fe_reim21, gai_im_negate, &fe_div, 0);
        gai.im = fe_reim21;

        return gai;
    }

    // gai_t ()* ==
    gai_t secp256k1_gai_conj(const gai_t *gai1) { // (gai1)*
        if(CPubKey::ecmult::secp256k1_fe_is_zero(&gai1->im))
            return *gai1;
        gai_t gai_conj = *gai1;
        gai_conj.im_negate = gai_conj.im_negate==0? 1: 0;
        return gai_conj;
    }
    int secp256k1_gai_equal(const gai_t *gai1, const gai_t *gai2) { // gai1 == gai2
        if(gai1->im_negate==gai2->im_negate && gai1->re_negate==gai2->re_negate) {
            int g1 = CPubKey::ecmult::secp256k1_fe_equal(&gai1->re, &gai2->re);
            int g2 = CPubKey::ecmult::secp256k1_fe_equal(&gai1->im, &gai2->im);
            return (g1 && g2) ? 1: 0;
        } else
            return 0;
    }

    // gai_t dot vector
    gai_t secp256k1_gai_dot(const std::pair<gai_t, gai_t> *gaivx, const std::pair<gai_t, gai_t> *gaivy) { // (gaivx, gaivy)
        std::pair<gai_t, gai_t> gaivx_conj;
        gaivx_conj.first = secp256k1_gai_conj(&gaivx->first);
        gaivx_conj.second = secp256k1_gai_conj(&gaivx->second);

        CPubKey::ecmult::secp256k1_fe gai_ae, gai_bf, gai_cg, gai_dh, gai_af, gai_be, gai_ch, gai_dg;
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
    uint256 secp256k1_scalar_get_uint256(const CPubKey::secp256k1_scalar *unit) {
        uint256 value;
        CPubKey::secp256k1_scalar_get_b32((unsigned char *)&value, unit);
        return value;
    }
    std::pair<uint256, uint256> secp256k1_scalar_get_uint256(const CPubKey::secp256k1_scalar *re, const CPubKey::secp256k1_scalar *im) {
        return std::make_pair(secp256k1_scalar_get_uint256(re), secp256k1_scalar_get_uint256(im));
    }
    std::pair<uint256, uint256> secp256k1_scalar_get_uint256(const gai_t *gai) {
        int overflow = 0;
        CPubKey::secp256k1_scalar unit_re, unit_im;
        CPubKey::secp256k1_scalar_set_int(&unit_re, 0);
        CPubKey::secp256k1_scalar_set_int(&unit_im, 0);
        CPubKey::secp256k1_scalar_set_b32(&unit_re, (const unsigned char *)&gai->re, &overflow);
        CPubKey::secp256k1_scalar_set_b32(&unit_im, (const unsigned char *)&gai->im, &overflow);
        return secp256k1_scalar_get_uint256(&unit_re, &unit_im);
    }

    // from gai_t to std::string
    std::string secp256k1_gai_ToString(const gai_t *gai, std::string str="") {
        std::pair<uint256, uint256> gai_reim = secp256k1_scalar_get_uint256(gai);
        if(gai_reim.first!=0 && gai_reim.second!=0)
            return tfm::format("secp256k1 gai %s \n Re: %s0x%s\n Im: %s0x%s\n", str.c_str(), gai->re_negate?"-":"", gai_reim.first.ToString().c_str(), gai->im_negate?"-":"", gai_reim.second.ToString().c_str());
        else if(gai_reim.second==0) // im == 0
            return tfm::format("secp256k1 gai %s \n Re: %s0x%s\n Im: zero\n", str.c_str(), gai->re_negate?"-":"", gai_reim.first.ToString().c_str());
        else // re == 0
            return tfm::format("secp256k1 gai %s \n Re: zero\n Im: %s0x%s\n", str.c_str(), gai->im_negate?"-":"", gai_reim.second.ToString().c_str());
    }

    key_test() {
        debugcs::instance() << "key_test" << debugcs::endl();

        /*
        CPubKey::secp256k1_scalar r, s;
        int overflow=0;
        int ret=1;
        std::vector<unsigned char> vchRS;
        vchRS.reserve(65);
        vchRS.push_back(0x04);
        for(int i=1; i<65; ++i)
            vchRS.push_back(0x10);
        CPubKey::secp256k1_scalar_set_b32(&r, &vchRS[1], &overflow);
        ret &= !overflow;
        CPubKey::secp256k1_scalar_set_b32(&s, &vchRS[33], &overflow);
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
        */

        // gai1 + gai2
        {
            gai_t gai1 = secp256k1_gai_create(-5, -8563);
            gai_t gai2 = secp256k1_gai_create(-156544, 1330000);
            gai_t gai3 = secp256k1_gai_add(&gai1, &gai2);
            std::string _test1 = secp256k1_gai_ToString(&gai3, std::string("gai1+gai2"));
            ::fprintf(stdout, "%s\n", _test1.c_str());
        }

        // gai1 - gai2
        {
            gai_t gai1 = secp256k1_gai_create(-1, -256);
            gai_t gai2 = secp256k1_gai_create(15, -128);
            gai_t gai3 = secp256k1_gai_sub(&gai1, &gai2);
            std::string _test1 = secp256k1_gai_ToString(&gai3, std::string("gai1-gai2"));
            ::fprintf(stdout, "%s\n", _test1.c_str());
        }

        // gai1 * gai2
        {
            gai_t gai1 = secp256k1_gai_create(-12345, 1254);
            gai_t gai2 = secp256k1_gai_create(152345, -113451);
            gai_t gai3 = secp256k1_gai_mul(&gai1, &gai2);
            std::string _test1 = secp256k1_gai_ToString(&gai3, std::string("gai1*gai2"));
            ::fprintf(stdout, "%s\n", _test1.c_str());
        }

        // gai1 / gai2
        {
            gai_t gai1 = secp256k1_gai_create(10654, -5536);
            gai_t gai2 = secp256k1_gai_create(523, 1012);
            gai_t gai3 = secp256k1_gai_div(&gai1, &gai2);
            std::string _test1 = secp256k1_gai_ToString(&gai3, std::string("gai1/gai2"));
            ::fprintf(stdout, "%s\n", _test1.c_str());
        }

        // (gai)*
        {
            gai_t gai1 = secp256k1_gai_create(-1, -256);
            gai_t gai2 = secp256k1_gai_conj(&gai1);
            std::string _test1 = secp256k1_gai_ToString(&gai2, std::string("(gai1)*"));
            ::fprintf(stdout, "%s\n", _test1.c_str());

            gai_t gai3 = secp256k1_gai_create(1, 256);
            gai_t gai4 = secp256k1_gai_conj(&gai3);
            std::string _test2 = secp256k1_gai_ToString(&gai4, std::string("(gai4)*"));
            ::fprintf(stdout, "%s\n", _test2.c_str());
        }

        // gai1 == gai2
        {
            gai_t gai1 = secp256k1_gai_create(-1, -256);
            gai_t gai2 = secp256k1_gai_create(-1, -256);
            int ret = secp256k1_gai_equal(&gai1, &gai2);
            ::fprintf(stdout, "(gai1==gai2) %d\n", ret);
        }

        // fe / fe
        {
            CPubKey::ecmult::secp256k1_fe fe1, fe2;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 23456712);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 1526);
            secp256k1_negate_ope::fe_div_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe / fe test 1 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 19276345);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 1511);
            secp256k1_negate_ope::fe_div_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe / fe test 2 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 196);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 15);
            secp256k1_negate_ope::fe_div_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe / fe test 3 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 17723);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 15);
            secp256k1_negate_ope::fe_div_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe / fe test 4 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
        }

        // fe % fe
        {
            CPubKey::ecmult::secp256k1_fe fe1, fe2;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 12345);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 7);
            secp256k1_negate_ope::fe_pow_to_negate(&fe1, 0, 1);
            secp256k1_negate_ope::fe_mod_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe %% fe test 1 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 12345);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 7);
            secp256k1_negate_ope::fe_pow_to_negate(&fe1, 0, 6);
            secp256k1_negate_ope::fe_mod_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe %% fe test 2 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
            CPubKey::ecmult::secp256k1_fe_set_int(&fe1, 12345);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe2, 3);
            CPubKey::ecmult::secp256k1_fe fe_1;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_1, 1);
            secp256k1_negate_ope::fe_pow_to_negate(&fe1, 0, 17);
            CPubKey::ecmult::secp256k1_fe_add(&fe1, &fe_1);
            CPubKey::ecmult::secp256k1_fe_normalize(&fe1);
            secp256k1_negate_ope::fe_mod_to_negate(&fe1, 0, &fe2, 0);
            ::fprintf(stdout, "fe %% fe test 3 %s\n", secp256k1_negate_ope::fe_ToString(&fe1).c_str());
        }

        // uint256 test
        {
            const uint256 u1("0x00002046b1c7938971a6089c7105fc15907b8f27ac8dfea9896c27c593a9a966");
            const uint256 u2("0x1856000000");
            const uint256 u3("0x23fd456ae7");
            ::fprintf(stdout, "uint256 mul 0x%s\n", (u1*u2).ToString().c_str());
            ::fprintf(stdout, "uint256 div 0x%s\n", (u1/u2).ToString().c_str());
            ::fprintf(stdout, "uint256 mod 0x%s\n", (u1%u2).ToString().c_str());
            ::fprintf(stdout, "uint256 group 0x%s\n", ((u1%u2+u1/u2-u2)%u2+u1).ToString().c_str());
        }

        // 3n + 1
        /*
        {
            CPubKey::ecmult::secp256k1_fe fe_1, fe_2, fe_3;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_1, 1);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_2, 2);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_3, 3);
            for(int i=1; i<10000; ++i) {
                CPubKey::ecmult::secp256k1_fe fe_n;
                CPubKey::ecmult::secp256k1_fe_set_int(&fe_n, i);
            rp:;
                if(CPubKey::ecmult::secp256k1_fe_is_odd(&fe_n)==1) {
                    secp256k1_negate_ope::fe_mul_to_negate(&fe_n, 0, &fe_3, 0);
                    secp256k1_negate_ope::fe_add_to_negate(&fe_n, 0, &fe_1, 0);
                } else
                    secp256k1_negate_ope::fe_div_to_negate(&fe_n, 0, &fe_2, 0);
                if(secp256k1_negate_ope::fe_normalize_to_cmp(&fe_n, &fe_1)<=0) {
                    // pass: 3n + 1 mod 1
                } else {
                    goto rp;
                }
            }
        }
        */

        // clear test
        /*
        {
            CPubKey::ecmult::secp256k1_fe fe_1, fe_2, fe_na;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_1, 1);
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_2, 3);
            CPubKey::ecmult::secp256k1_fe_negate(&fe_na, &fe_1, 1);
            CPubKey::ecmult::secp256k1_fe_add(&fe_1, &fe_2);
            CPubKey::ecmult::secp256k1_fe_add(&fe_na, &fe_2);
            ::fprintf(stdout, "fe_2 clear test %s\n", secp256k1_fe_ToString(&fe_2).c_str());
            ::fprintf(stdout, "fe_1 clear test %s\n", secp256k1_fe_normalize_to_ToString(&fe_1).c_str());
            ::fprintf(stdout, "fe_na clear test %s\n", secp256k1_fe_normalize_to_ToString(&fe_na).c_str());
            CPubKey::ecmult::secp256k1_fe fe_zero;
            CPubKey::ecmult::secp256k1_fe_set_int(&fe_zero, 0);
            ::fprintf(stdout, "fe_zero test 0 %s\n", secp256k1_fe_ToString(&fe_zero).c_str());
            CPubKey::ecmult::secp256k1_fe fe_mul;
            CPubKey::ecmult::secp256k1_fe_mul(&fe_mul, &fe_2, &fe_2);
            ::fprintf(stdout, "fe_mul clear test %s\n", secp256k1_fe_normalize_to_ToString(&fe_mul).c_str());
        }
        */

        assert(!"secp256k1 test");
    }
};
#ifdef DEBUG
//key_test key_test_obj;
#endif
