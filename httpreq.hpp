#pragma once

#include "expected.hpp"
#include "future.hpp"

#include <unordered_map>
#include <string>

#define HTTPREQ 1

typedef std::unordered_map<std::string, std::string> HeaderMap;

struct HTTPResponse
{
    explicit HTTPResponse(HeaderMap&& eat) : headers(std::move(eat)) {}
    HTTPResponse() = default;
    int status_code;
    std::string reason_msg;
    HeaderMap headers;
    std::string document;
};

class HTTPError : public Show
{
public:
    enum HTTPErrorT
    {
        TimedOutError,
        URLError,
        PortError,
        ConnectionError,
        ResponseError,
        GaiError,
        TLSError
    };
    HTTPErrorT err() const
    {
        return err_;
    }

    HTTPError() {}
    HTTPError(HTTPErrorT er, std::string&& ex = "");
    const char* show() const override;
private:
    std::string msg_; // human readable version
    HTTPErrorT err_; // type of error
};

typedef Expected<HTTPResponse, HTTPError> ReqResult;

// const HeaderMap default_headers = {
//     {"Connection", "close"}
// };

struct RequestOp
{
    RequestOp() : timeout(10), verify(true), 
        request_headers({{"Connection", "close"}}) {}
    RequestOp& operator+(const RequestOp& op)
    {
        if (op.timeout != 10)
            this->timeout = op.timeout;
        if (op.verify != true)
            this->verify = op.verify;
        if (op.request_headers.count("Connection") > 0
            && op.request_headers.at("Connection") != "close")
            this->request_headers = op.request_headers;
        return *this;
    }
    uint32_t timeout;
    bool verify;
    HeaderMap request_headers;
};

RequestOp http_timeout(uint32_t val);

RequestOp http_tls_verify(bool val);

RequestOp http_request_headers(HeaderMap&& headers);

const RequestOp def_op;


ReqResult http_request(const char* addr,
            const RequestOp opts = def_op);

ReqResult http_request(char* addr,
            const RequestOp opts = def_op);

ReqResult http_request(std::string addr,
            const RequestOp opts = def_op);

Future<ReqResult> http_future(const char* addr,
                              const RequestOp opts = def_op);

Future<ReqResult> http_future(const std::string& addr,
                              const RequestOp opts = def_op);
