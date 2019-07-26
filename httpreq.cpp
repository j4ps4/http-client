#include "future.hpp"
#include "httpreq.hpp"

#include <string>
#include <algorithm>
#include <sstream>
#include <limits>
#include <functional>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>

namespace
{
    ReqResult request_handler(const char* addr,
                             const RequestOp timeout);

    /* Get stuff from address. */
    void parse_url(const char* addr, std::string& host,
        std::string& route, bool& https, int& port, bool& found_port);
    /* Read the HTTP headers into a map */
    HeaderMap read_headers(char*, size_t);
    const char* cert_error(long code);

    bool read_fixed_length(int* socket_fd, SSL* ssl, size_t to_read,
        std::string& out, bool https);
    bool read_chunks(int* socket_fd, SSL* ssl, std::string& out, bool https);

    void initSSL();
    SSL* getSSL();
    std::string get_SSL_errors();
    SSL_CTX* ctx = nullptr;
    pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

    void CTX_deleter()
    {
        SSL_CTX_free(ctx);
    }

    void SSL_deleter(SSL* ptr)
    {
        if (!ptr)
            return;
        SSL_shutdown(ptr);
        SSL_free(ptr);
    }
    
    void socket_deleter(int* sfd)
    {
        if (sfd)
            close(*sfd);
    }

    template <typename OutputIt>
    void fillZeros(OutputIt fst, size_t count)
    {
        std::fill_n(fst, count, '\0');
    }

    const size_t EB_SIZE = 100;
    const size_t READ_SIZE = 4096;
    const size_t TOO_LONG_HEADER = 40000;
}


HTTPError::HTTPError(HTTPErrorT er, std::string&& ex) : err_(er)
{
    if (ex.empty())
    {
        switch (er)
        {
            case TimedOutError:
                msg_ = "TimedOutError: connection timed out";
                break;
            case URLError:
                msg_ = "URLError: malformed url";
                break;
            case PortError:
                msg_ = "PortError: port number out of range";
                break;
            case ConnectionError:
                msg_ = "ConnectionError: could not connect to host";
                break;
            case ResponseError:
                msg_ = "ResponseError: error reading response";
                break;
            case GaiError:
                msg_ = "GaiError: error in address resolution";
                break;
            case TLSError:
                msg_ = "TLSError: generic TLS error";
                break;
            default:
                abort();
        }
    }
    else
    {
        switch (er)
        {
            case TimedOutError:
                msg_ = "TimedOutError: " + ex;
                break;
            case URLError:
                msg_ = "URLError: " + ex;
                break;
            case PortError:
                msg_ = "PortError: " + ex;
                break;
            case ConnectionError:
                msg_ = "ConnectionError: " + ex;
                break;
            case ResponseError:
                msg_ = "ResponseError: " + ex;
                break;
            case GaiError:
                msg_ = "GaiError: " + ex;
                break;
            case TLSError:
                msg_ = "TLSError: " + ex;
                break;
            default:
                abort();
        }
    }
}

const char* HTTPError::show() const
{
    return msg_.c_str();
}


ReqResult http_request(const char* addr,
            const RequestOp opts)
{
    return request_handler(addr, opts);
}

ReqResult http_request(char* addr,
            const RequestOp opts)
{
    return request_handler(addr, opts);
}

ReqResult http_request(std::string addr,
            const RequestOp opts)
{
    return request_handler(addr.c_str(), opts);
} 

Future<ReqResult> http_future(const char* addr,
                              const RequestOp opts)
{
    return make_future(request_handler, addr, opts);
}

Future<ReqResult> http_future(const std::string& addr,
                              const RequestOp opts)
{
    return make_future(request_handler, addr.c_str(), opts);
}

RequestOp http_timeout(uint32_t val)
{
    RequestOp out;
    out.timeout = val;
    return out;
}

RequestOp http_tls_verify(bool val)
{
    RequestOp out;
    out.verify = val;
    return out;
}

RequestOp http_request_headers(HeaderMap&& headers)
{
    RequestOp out;
    out.request_headers = headers;
    return out;
}

namespace
{

ReqResult request_handler(const char* addr,
                            const RequestOp opts)
{
    char error_buf[EB_SIZE];
    std::string host, route;
    bool https;
    bool found_port;
    int port;
    static pthread_once_t init_done = PTHREAD_ONCE_INIT;

    std::unique_ptr<int, void(*)(int*)> my_socket(nullptr, socket_deleter);
    std::unique_ptr<SSL, void(*)(SSL*)> my_ssl(nullptr, SSL_deleter);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> result(nullptr, freeaddrinfo);

    // *** Split address into host/route ***

    parse_url(addr, host, route, https, port, found_port);

    if (https)
    {
        pthread_once(&init_done, initSSL);
        my_ssl.reset(getSSL());
    }

    // *** Obtain IP address ***

    if (!found_port)
        port = https ? 443 : 80;
    else
    {
        if (port < 0 || port > std::numeric_limits<uint16_t>::max())
            return unexpected<HTTPResponse>(HTTPError(HTTPError::PortError));
    }

    addrinfo* gai_res; 
    addrinfo hints;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_UNSPEC; /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Byte stream socket */
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_TCP; /* TCP protocol */
    int s = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &gai_res);
    if (s != 0) {
        std::string err = gai_strerror(s);
        return unexpected<HTTPResponse>(HTTPError(HTTPError::GaiError, std::move(err)));
    }

    result.reset(gai_res);

    // *** Try to connect ***

    // result from getaddrinfo should never be null
    int sfd = socket(result.get()->ai_family, result.get()->ai_socktype, result.get()->ai_protocol);
    if (sfd == -1)
    {
        perror("request_handler: socket");
        exit(1);
    }

    // Set timeouts for socket operations
    if (opts.timeout > 0)
    {
        timeval tv{opts.timeout, 0};
        if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(timeval)) == -1)
        {
            perror("setsocktopt");
            exit(1);
        }
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(timeval)) == -1)
        {
            perror("setsocktopt");
            exit(1);
        }
    }

    my_socket.reset(&sfd);

    int c_rv = connect(sfd, result.get()->ai_addr, result.get()->ai_addrlen);
    if (c_rv == -1)
    {
        if (errno == EINPROGRESS)
            return unexpected<HTTPResponse>(HTTPError(HTTPError::TimedOutError,
                "connect() taking longer than "+std::to_string(opts.timeout)+" seconds"));
        char* err_str = strerror_r(errno, error_buf, EB_SIZE);
        return unexpected<HTTPResponse>(HTTPError(HTTPError::ConnectionError, std::string(err_str)));
    }

    // *** TLS handshake ***

    if (https)
    {
        // Take control of socket
        SSL_set_fd(my_ssl.get(), *my_socket);
        // Enable SNI extension
        SSL_set_tlsext_host_name(my_ssl.get(), host.c_str());
        int err = SSL_connect(my_ssl.get());
        if (err <= 0)
        {
            return unexpected<HTTPResponse>(HTTPError(HTTPError::TLSError, get_SSL_errors()));
        }
        if (opts.verify)
        {
            X509* cert = SSL_get_peer_certificate(my_ssl.get());
            if (cert == nullptr)
                return unexpected<HTTPResponse>(HTTPError(HTTPError::TLSError, "server didn't present a certificate"));
            X509_free(cert);
            long res = SSL_get_verify_result(my_ssl.get());
            if (res != X509_V_OK)
            {
                return unexpected<HTTPResponse>(HTTPError(HTTPError::TLSError, 
                    std::string("certificate verification failed: ")+cert_error(res)));
            }
        }
    }

    // *** HTTP GET request ***

    std::stringstream req_stream;
    req_stream << "GET " << route << " HTTP/1.1\r\nHost: " << host << "\r\n";
    for (auto& [k, v] : opts.request_headers)
        req_stream << k << ": " << v << "\r\n";
    req_stream << "\r\n";
    auto msg_s = req_stream.str();
    auto msg_len = msg_s.length();

    /* Write http msg to the socket and read a response. */
    ssize_t nwrite;
    if (https)
        nwrite = (ssize_t) SSL_write(my_ssl.get(), msg_s.data(), msg_len);
    else
        nwrite = write(*my_socket, msg_s.data(), msg_len);

    if (nwrite != (ssize_t)msg_len)
    {
        if (errno == EINPROGRESS || errno == EAGAIN)
            return unexpected<HTTPResponse>(HTTPError(HTTPError::TimedOutError));
        perror("request_handler: write");
        exit(1);
    }

    // *** Read enough of response to determine header length ***

    const size_t HEADER_READ = 512;
    std::array<char, HEADER_READ> buf;
    std::string cat_buf;
    cat_buf.reserve(HEADER_READ);
    buf.fill('\0');
    size_t to_read = -1;
    size_t read_total = 0;
    size_t needle_lock;
    ssize_t nread = 0;
    if (https)
    {
        for (;;)
        {
            nread = (ssize_t) SSL_read(my_ssl.get(), buf.data(), HEADER_READ);
            if (nread == 0)
                break;
            if (nread < 0)
            {
                if (errno == EINPROGRESS || errno == EAGAIN)
                    return unexpected<HTTPResponse>(HTTPError(HTTPError::TimedOutError));
                return unexpected<HTTPResponse>(HTTPError(HTTPError::TLSError, get_SSL_errors()));
            }
            cat_buf.insert(cat_buf.cend(), buf.data(), buf.data() + nread);
            char* needle = strstr(buf.data(), "\r\n\r\n");
            if (needle != nullptr)
            {
                needle_lock = read_total + (needle - buf.data());
                break;
            }
            read_total += nread;
            if (read_total >= TOO_LONG_HEADER)
                return unexpected<HTTPResponse>(HTTPError(HTTPError::ResponseError,
                    "excessively long response header"));
        } 
    } 
    else
    {
        for (;;)
        {
            nread = read(*my_socket, buf.data(), HEADER_READ);
            if (nread == 0)
                break;
            if (nread < 0)
            {
                if (errno == EINPROGRESS || errno == EAGAIN)
                    return unexpected<HTTPResponse>(HTTPError(HTTPError::TimedOutError));
                perror("request_handler: read");
                exit(1);
            }
            cat_buf.insert(cat_buf.cend(), buf.data(), buf.data() + nread);
            char* needle = strstr(buf.data(), "\r\n\r\n");
            if (needle != nullptr)
            {
                needle_lock = read_total + (needle - buf.data());
                break;
            }
            read_total += nread;
            if (read_total >= TOO_LONG_HEADER)
                return unexpected<HTTPResponse>(HTTPError(HTTPError::ResponseError,
                    "excessively long response header"));
        }
    }

    if (cat_buf.empty())
        return unexpected<HTTPResponse>(HTTPError(HTTPError::ResponseError, "zero length response"));

    if (cat_buf.substr(0, 4) != "HTTP")
        return unexpected<HTTPResponse>(HTTPError(HTTPError::ResponseError, "non-HTTP response"));

    // Determine response code
    auto space1 = cat_buf.find(' ');
    auto space2 = cat_buf.find(' ', space1 + 1);
    auto eol = cat_buf.find('\r', space2 + 1);
    int status_code = std::stoi(cat_buf.substr(space1+1, space2-space1-1));
    std::string reason_msg = cat_buf.substr(space2+1, eol-space2-1);

    // *** Read headers into map ***

    HTTPResponse out(read_headers(cat_buf.data(), needle_lock));
    out.status_code = status_code;
    out.reason_msg = reason_msg;

    // Header not needed anymore
    cat_buf.erase(0, needle_lock + 4);

    // *** Read response body ***
    bool read_ret = true;

    // Content-Length is the message body length
    if (out.headers.count("Content-Length") > 0)
    {
        const int LONG = 1000000;
        // Content-Type == text/html  
        to_read = stoull(out.headers["Content-Length"]);
        to_read -= cat_buf.length();
        if (to_read > 0) // We may already have the whole response
        {
            if (to_read < LONG)
                read_ret = read_fixed_length(my_socket.get(), my_ssl.get(), to_read, cat_buf, https);
            else
                read_ret = read_fixed_length(my_socket.get(), my_ssl.get(), -1, cat_buf, https);
        }
    }
    else if (out.headers.count("Transfer-Encoding") > 0 && 
                out.headers["Transfer-Encoding"] == "chunked")
    {
        read_ret = read_chunks(my_socket.get(), my_ssl.get(), cat_buf, https);
        // read_ret = read_fixed_length(*my_socket, my_ssl.get(), -1, cat_buf, https);
    }
    else
    {
        read_ret = read_fixed_length(my_socket.get(), my_ssl.get(), -1, cat_buf, https);
    }

    if (!read_ret)
        return unexpected<HTTPResponse>(HTTPError(HTTPError::TimedOutError));
    out.document = cat_buf;
    return ReqResult(std::move(out));
}

ssize_t read_gen(int* sock, SSL* ssl_sock, bool https, void* buf, size_t nbytes)
{
    if (https)
        return (ssize_t)SSL_read(ssl_sock, buf, nbytes);
    else
        return read(*sock, buf, nbytes);
}

bool read_fixed_length(int* socket_fd, SSL* ssl, size_t to_read,
                       std::string& out, bool https)
{
    const size_t OUT_SIZE = 25000;
    size_t read_left = to_read;
    ssize_t nread;
    size_t my_buf_s = to_read == (size_t)-1 ? READ_SIZE : to_read;
    size_t out_str_s = to_read == (size_t)-1 ? OUT_SIZE : to_read;
    std::unique_ptr<char[]> buf(new char[my_buf_s]);
    out.reserve(out.size() + out_str_s);
    while (read_left > 0)
    {
        // nread = (ssize_t) SSL_read(ssl, buf.get(), std::min(my_buf_s, read_left));
        nread = read_gen(socket_fd, ssl, https, buf.get(), std::min(my_buf_s, read_left));
        if (nread == 0)
            break;
        if (nread < 0)
        {
            if (errno == EINPROGRESS || errno == EAGAIN)
                return false;
            if (https)
                std::cerr << "request_handler: SSL_read: " << get_SSL_errors() << std::endl;
            else
                perror("request_handler: read");
            exit(1);
        }
        read_left -= nread;
        out.insert(out.cend(), buf.get(), buf.get() + nread);
    }
    // else
    // {
    //     while (read_left > 0)
    //     {
    //         nread = read(socket_fd, buf.get(), std::min(my_buf_s, read_left));
    //         // std::cout << "read " << nread << " bytes\n";
    //         if (nread == 0)
    //             break;
    //         if (nread == -1)
    //         {
    //             if (errno == EINPROGRESS || errno == EAGAIN)
    //                 return false;
    //             perror("request_handler: read");
    //             exit(1);
    //         }
    //         read_left -= nread;
    //         out.insert(out.cend(), buf.get(), buf.get() + nread);
    //         if (read_left == 0)
    //             break;
    //     }
    // }
    out.shrink_to_fit();
    return true;
}

bool read_chunks(int* socket_fd, SSL* ssl, std::string& out, bool https)
{
    // assumes that trailing "/r/n" from previous chunk has been read
    auto read_buffer = [&](std::string& str){
        char buf[12];
        ssize_t nread;
        size_t loc;
        for (;;)
        {
            nread = read_gen(socket_fd, ssl, https, buf, 12);
            str.insert(str.cend(), buf, buf + nread);
            loc = str.find("\r\n");
            if (loc != std::string::npos)
                break;
        }
        return loc;
    };
    // returns success indication, chunk size, characters after “/r/n"
    // and number characters to be read in chunk
    // needs to do special handling if next chunk begins in the buffer
    std::function<std::tuple<bool,size_t,std::string,size_t>(std::string&, size_t)>
    det_chunk_size = [&](std::string& str, size_t loc)
                            ->std::tuple<bool,size_t,std::string,size_t>{
        if (loc == (size_t)-1)
        {
            loc = str.find("\r\n");
            if (loc == std::string::npos)
                return {false, 0, "", 0};
        }
        auto ss = str.substr(0, loc);
        auto size = std::stoi(ss, 0, 16);
        if (size == 0) // last chunk
            return {true, 0, "", 0};
        auto out = str.substr(loc + 2);
        auto left = size - out.size();
        if (out.size() > (size_t)size + 2) // overflows
        {
            auto next_crlf = out.find("\r\n");
            auto next_chunk = out.substr(next_crlf + 2);
            auto previous_chunk = out.substr(0, next_crlf);
            auto [succ, new_size, new_chunk, new_left] = det_chunk_size(next_chunk, -1);
            if (!succ)
            {
                loc = read_buffer(next_chunk);
                std::tie(succ, new_size, new_chunk, new_left) = det_chunk_size(next_chunk, loc);
            }
            out = previous_chunk + new_chunk;
            left = new_left;
        }
        return {true, size, out, left};
    };
    size_t locat = -1;
    std::string next;
    bool succ;
    size_t ch_size;
    size_t left;
    ssize_t nread;
    if (out.size() >= 12)
    {
        std::tie(succ, ch_size, next, left) = det_chunk_size(out, locat);
        if (!succ)
        {
            locat = read_buffer(out);
            std::tie(succ, ch_size, next, left) = det_chunk_size(out, locat);
        }
    }
    else
    {
        locat = read_buffer(out);
        std::tie(succ, ch_size, next, left) = det_chunk_size(out, locat);
    }
    out = next; // discard garbage
    if (ch_size == 0)
        return true;
    std::vector<char> buf;
    buf.reserve(left + 2);
    for (;;)
    {
        size_t read_left = left + 2;
        while (read_left > 0)
        {
            nread = read_gen(socket_fd, ssl, https, buf.data(), read_left);
            read_left -= nread;
            out.insert(out.cend(), buf.data(), buf.data()+nread);
        }
        out.pop_back(); out.pop_back(); // erase crlf
        next = "";
        locat = read_buffer(next);
        std::tie(succ, ch_size, next, left) = det_chunk_size(next, locat);
        if (ch_size == 0)
            break;
        if (buf.capacity() < left + 2)
            buf.reserve(left + 2);
        out.insert(out.cend(), next.begin(), next.end());
    }
    return true;
}

void parse_url(const char* addr, std::string& host,
    std::string& route, bool& https, int& port, bool& found_port)
{
    const char http_prefix[] = "http://";
    const char https_prefix[] = "https://";
    char* sin_prefix;
    bool allocd = true;
    // todo needs error handling
    if (strstr(addr, http_prefix) == addr)
    {
        https = false;
        size_t len = strlen(addr) + 1 - strlen(http_prefix);
        sin_prefix = (char*) malloc(len * sizeof(char));
        strncpy(sin_prefix, addr + strlen(http_prefix), len);
    }
    else if (strstr(addr, https_prefix) == addr)
    {
        https = true;
        size_t len = strlen(addr) + 1 - strlen(https_prefix);
        sin_prefix = (char*) malloc(len * sizeof(char));
        strncpy(sin_prefix, addr + strlen(https_prefix), len);
    }
    else
    {
        https = false;
        sin_prefix = const_cast<char*>(addr);
        allocd = false;
    }
    const char* firstslash = strchr(sin_prefix, '/');
    if (firstslash == nullptr) /* not found */
    {
        host = sin_prefix;
        route = "/";
    }
    else
    {
        size_t len = firstslash - sin_prefix;
        host = sin_prefix;
        host.erase(len);
        route = firstslash;
    }
    size_t colon = host.find(':');
    if (colon != std::string::npos)
    {
        found_port = true;
        port = std::stoi(host.substr(colon+1));
        host.erase(colon);
    }
    else
    {
        found_port = false;
    }
    if (allocd)
        free(sin_prefix);
}

HeaderMap read_headers(char* head_str, size_t header_len)
{
    auto colon_separate = [](char* ptr)->std::tuple<char*,char*,char*>{
        auto colon = strchr(ptr, ':');
        if (colon == nullptr)
            return std::make_tuple(nullptr, nullptr, nullptr);
        auto endl = strchr(colon, '\r');
        return std::make_tuple(colon, colon+2, endl);
    };
    HeaderMap out;
    // skip status line
    char* ptr = strchr(head_str, '\n') + 1;
    for (;;)
    {
        auto [hname_end, hcont, hcont_end] = colon_separate(ptr);
        if (hname_end == nullptr)
            break;
        char end_chr1 = *hname_end;
        char end_chr2 = *hcont_end;
        ptr[hname_end - ptr] = '\0';
        ptr[hcont_end - ptr] = '\0';
        // bug in libstdc++
        if (strcmp(ptr, "Alt-Svc") != 0)
            out[std::string(ptr)] = std::string(hcont);
        ptr[hname_end - ptr] = end_chr1;
        ptr[hcont_end - ptr] = end_chr2;
        if (hcont_end - head_str >= (ssize_t)header_len)
            break;
        ptr = hcont_end + 2;
    }
    return out;
}

void initSSL()
{
    // phtread_once
    const SSL_METHOD* meth = TLS_client_method();
    ctx = SSL_CTX_new(meth);
    // Needed in order to verify server certificate
    SSL_CTX_set_default_verify_paths(ctx);
    // The OpenSSL library can handle renegotiations automatically, so
    // tell it to do so.
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    atexit(CTX_deleter);
}

SSL* getSSL()
{
    SSL* ssl;
    pthread_mutex_lock(&mut);
    ssl = SSL_new(ctx);
    pthread_mutex_unlock(&mut);
    if (!ssl)
    {
        std::cerr << "request_handler: SSL_new: " << get_SSL_errors() << std::endl;
        exit(1);
    }
    return ssl;
}

std::string get_SSL_errors()
{
    char err_buf[100];
    std::string out;
    while (uint64_t err = ERR_get_error())
    {
        ERR_error_string_n(err, err_buf, 100);
        out += err_buf;
        out += '\n';
    }
    return out;
}

const char* cert_error(long code)
{
    switch (code)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        return "issuer certificate could not be found";
    case X509_V_ERR_UNABLE_TO_GET_CRL:
        return "CRL of the certificate could not be found";
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        return "certificate signature could not be decrypted";
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        return "public key in the certificate SubjectPublicKeyInfo could not be read";
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        return "signature of the certificate is invalid";
    case X509_V_ERR_CERT_NOT_YET_VALID:
        return "certificate is not yet valid";
    case X509_V_ERR_CERT_HAS_EXPIRED:
        return "certificate has expired";
    case X509_V_ERR_CRL_NOT_YET_VALID:
        return "CRL is not yet valid";
    case X509_V_ERR_CRL_HAS_EXPIRED:
        return "CRL has expired";
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        return "certificate notBefore field contains an invalid time";
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        return "certificate notAfter field contains an invalid time";
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        return "certificate is self-signed and untrusted";
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        return "root certificate could not be found";
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "issuer certificate could not be found";
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        return "unable to verify leaf signature";
    case X509_V_ERR_CERT_REVOKED:
        return "certificate has been revoked";
    case X509_V_ERR_INVALID_CA:
        return "CA certificate is invalid";
    case X509_V_ERR_INVALID_PURPOSE:
        return "supplied certificate cannot be used for the specified purpose";
    case X509_V_ERR_CERT_UNTRUSTED:
        return "root CA is not marked as trusted for the specified purpose";
    case X509_V_ERR_CERT_REJECTED:
        return "root CA is marked to reject the specified purpose";
    default:
        return "unspecified error";
    }
}


// std::ostream& operator<< (std::ostream& os, const ReqResult& res)
// {
//     if (res.ok())
//         os << "value(" << res.value() << ")";
//     else
//         os << "error(" << res.error() << ")";
//     return os;
// }

} // namespace
