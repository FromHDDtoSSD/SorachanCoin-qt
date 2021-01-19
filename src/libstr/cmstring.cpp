// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <libstr/cmstring.h>

// test OK (Windows and Linux/UNIX)
class CMString_test {
public:
    CMString_test() {
        CMString str = CMString(L"cats") += 4;
        str += CMString("doge") + L"doge";
        str += CMString(std::string("mike")) + std::wstring(L"neko");
        str += CMString(2) + 5;
        str += 2.718;
        str += CMString(3) + '.' + "14";
        assert(str=="cats4dogedogemikeneko252.7183.14");
        CMString si = 777;
        assert(si==L"777");
        CMString sv = L"sfrdt";

        CDataStream stream;
        stream << str << si << sv;

        {
            CMString str1, str2, str3;
            stream >> str1 >> str2 >> str3;
            assert(str1=="cats4dogedogemikeneko252.7183.14");
            assert(str2==L"777");
            assert(str3==L"sfrdt");
        }
    }
};
CMString_test cmstring;
