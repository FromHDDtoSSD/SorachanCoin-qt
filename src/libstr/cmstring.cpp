// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <libstr/cmstring.h>

// test
class CMString_test {
public:
    CMString_test() {
        CMString str = CMString(L"cats") += 4;
        str += CMString("doge") + L"doge";
        str += CMString(std::string("mike")) + std::wstring(L"neko");
        str += CMString(2) + 5;
        str += 2.718;
        assert(str=="cats4dogedogemikeneko252.718");
        CMString si = 777;
        assert(si==L"777");
    }
};
CMString_test cmstring;
