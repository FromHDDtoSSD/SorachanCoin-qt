// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <libstr/cmstring.h>
#include <libstr/movestream.h>

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
        CMString fo, f1;
        fo.format(L"%d", 456);
        f1.format("%d", 666);
        fo.formatcat((f1+"%d").w_str(), 222);

        CMString nfo;
        nfo.swap(std::move(fo));
        assert(fo==L"");

        CMString nnfo(std::move(nfo));
        assert(nfo=="");

        CDataStream stream;
        stream << str << si << sv << nnfo;

        {
            CMString str1, str2, str3, str4;
            stream >> str1 >> str2 >> str3 >> str4;
            assert(str1=="cats4dogedogemikeneko252.7183.14");
            assert(str2==L"777");
            assert(str3==L"sfrdt");
            assert(str4=="456666222");
        }

        CMoveStream mstream;
        mstream << str << si << sv << nnfo;

        CMoveStream m2stream(std::move(mstream));
        assert(mstream.empty());
        {
            CMString str1, str2, str3, str4;
            m2stream >> str1 >> str2 >> str3 >> str4;
            assert(str1=="cats4dogedogemikeneko252.7183.14");
            assert(str2==L"777");
            assert(str3==L"sfrdt");
            assert(str4=="456666222");
        }
    }
};
CMString_test cmstring;
