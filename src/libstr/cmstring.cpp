// Copyright (c) 2019-2021 The SorachanCoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <libstr/cmstring.h>
#include <libstr/movestream.h>
#include <random/random.h>

//
// CMString test OK (Windows and Linux/UNIX)
//
//void CMString_test() {}
void CMString_test() {
        CMString str = CMString(L"cats") += 456;
        str += CMString("doge") + L"doge";
        str += CMString(std::string("mike")) + std::wstring(L"neko");
        str += CMString(2) + 5;
        str += 2.718;
        str += CMString(3) + '.' + "14";
        const char *cstr = str.c_str();
        assert(str=="cats456dogedogemikeneko252.7183.14");
        assert(str=="cats456dogedogemikeneko252.7183.14");
        assert(cstr==str.c_str());
        str = "doge445566";
        assert(str==L"doge445566");
        assert(str=="doge445566");
        cstr = str.c_str();
        assert(cstr==str.c_str());
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
            assert(str1=="doge445566");
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
            assert(str1=="doge445566");
            assert(str2==L"777");
            assert(str3==L"sfrdt");
            assert(str4=="456666222");
        }

        CMString wsd("format %02d", 5);
        assert(wsd=="format 05");

        for(int i=0; i<1000; ++i) {
            CMString swt(L"format_swrtfz");
            assert(swt=="format_swrtfz");
            prevector<128, char> vch;
            vch.assign(swt.c_str(), swt.c_str()+swt.length());
            swt="wdqa_swyf";
            vch.insert(vch.end(), swt.c_str(), swt.c_str()+swt.length());
            assert(vch[17]=='_');
        }

        for(int i=0; i<1000; ++i) {
            static const char *table = "abcdefghijklmnopqr123456789";
            unsigned char buf[18]={0};
            for(int k=0; k<=i%17; ++k) {
                unsigned char ch;
                latest_crypto::random::GetStrongRandBytes(&ch, 1);
                buf[k] = table[(int)ch%(::strlen(table))];
            }
            CMString strg(CMString(std::string("fes").c_str()) + (char *)buf);
            assert(strg==("fes"+CMString((char *)buf)));
        }
}
