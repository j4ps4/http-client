#include "httpreq.hpp"
#include "operators.hpp"

#include <iostream>
#include <utility>
#include <fstream>

using namespace std;

// nullptr_t printer(HTTPResponse resp1, HTTPResponse resp2)
// {
//     cout << resp1.status_code << " " << resp1.reason_msg << endl;
//     cout << resp2.status_code << " " << resp2.reason_msg << endl;
//     return nullptr;
// }

// auto combine(ReqResult fst, int snd)
// {
//     if (fst)
//     {
//         return fst.value().body.at(snd);
//     }
//     else
//         return '\0';
// }


int main(int argc, char const *argv[])
{
    // ftp.cs.vu.nl
    auto resp = http_request(argv[1], http_request_headers({{"Connection", "close"}, {"User-Agent", "curl"}}));
    if (!resp)
    {
        cerr << resp.error() << endl;
        return 1;
    }
    // ofstream stream("output");
    cout << resp.value() << endl;
    auto& doc = resp.value().document;
    cout << resp.value().headers << endl;
    cout << doc << endl;
    // stream.write(doc.data(), doc.size());
    return 0;
}
