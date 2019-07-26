#include "httpreq.hpp"
#include "operators.hpp"

#include <iostream>
#include <utility>
#include <fstream>

using namespace std;


int main(int argc, char const *argv[])
{
    if (argc != 2)
    {
        cerr << "usage: http-client <URL>\n";
        return 1;
    }
    auto resp = http_request(argv[1], http_request_headers({{"Connection", "close"}, {"User-Agent", "curl"}}));
    if (!resp)
    {
        cerr << resp.error() << endl;
        return 1;
    }
    cout << resp.value() << endl;
    auto& doc = resp.value().document;
    cout << resp.value().headers << endl;
    cout << doc << endl;
    return 0;
}
