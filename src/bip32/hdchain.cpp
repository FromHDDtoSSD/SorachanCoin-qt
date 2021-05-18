
#include <bip32/hdchain.h>
#include <crypto/hmac_sha512.h>

static std::vector<std::string> bip39_word_list() {
    return {"tokyonikonaideitadakitai",
            "omochi",
            "kinshu",
            "itutunoko",
            "kokorowohitotuni",
            "iekaradenaide",
            "tokyokaradenaidekudasai",
            "kokoonorikirimasho",
            "watashinodeban",
            "tonainochosadesu",
            "denkiwokeshite",
            "kibouwomuneni"};
}

static bool len_check(int8_t size, const std::vector<int8_t> &lens) {
    for(auto ite: lens) {
        if(size==ite)
            return true;
    }
    return false;
}

static uint256 bytes_to_mnemonic(SecureBytes mnemonic_bytes) {
    if(! len_check(mnemonic_bytes.size(), {16, 20, 24, 28, 32}))
        throw std::runtime_error("Data length should be one of the following: [16, 20, 24, 28, 32], but it is {len(mnemonic_bytes)}.");

    std::vector<std::string> word_list = bip39_word_list();
    uint256 key = hash_basis::Hash(mnemonic_bytes.data(), mnemonic_bytes.data()+mnemonic_bytes.size());

    int32_t word_size=0;
    for(const auto &ite: word_list) {
        word_size += ite.size();
    }
    unsigned char *data = new(std::nothrow) unsigned char[word_size];
    if(! data)
        throw std::runtime_error("bytes_to_mnemonic out of memory.");
    unsigned char *wc=data;
    for(const auto &ite: word_list) {
        std::memcpy(wc, ite.c_str(), ite.size());
        wc+=ite.size();
    }

    unsigned char buf[64];
    latest_crypto::CHMAC_SHA512((const unsigned char *)&key, sizeof(key)).Write(data, word_size).Finalize(buf);
    uint256 hash;
    std::memcpy(&hash, buf, 32);
    delete [] data;
    return hash;
}

static uint256 generate_mnemonic() {
    SecureBytes mnemonic_bytes = token_bytes(32);
    return bytes_to_mnemonic(std::move(mnemonic_bytes));
}

static uint256 generate_priv_mnemonic() {
    SecureBytes mnemonic_bytes = privKey_bytes();
    return bytes_to_mnemonic(std::move(mnemonic_bytes));
}

// test
#include <util.h>
class bip39_test {
public:
    bip39_test() {
        debugcs::instance() << "bip39 test" << debugcs::endl();
        //debugcs::instance() << generate_mnemonic().ToString() << debugcs::endl();
        debugcs::instance() << generate_priv_mnemonic().ToString() << debugcs::endl();
        //util::Sleep(3000);
    }
    ~bip39_test() {}
};
#ifdef DEBUG
bip39_test bip39_obj;
#endif
