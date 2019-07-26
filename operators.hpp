#pragma once

#ifdef HTTPREQ

std::ostream& operator<< (std::ostream& os, const HeaderMap& map)
{
    for (auto& [k, v] : map)
        os << k << ": " << v << std::endl;
    return os;
}

std::ostream& operator<< (std::ostream& os, const HTTPResponse& resp)
{
    os << "HTTPResponse: status: " << resp.status_code << " " << resp.reason_msg << ", "
       << resp.headers.size() << " headers, document: " << resp.document.size() << " bytes";
    return os;
}

template<typename T1, typename E1>
std::ostream& operator<< (std::ostream& os, const Expected<T1, E1>& exp)
{
    if (exp.ok_)
        os << "value(" << exp.value_ << ")";
    else
        os << "error(" << exp.error_ << ")";
    return os;
}

#endif

std::ostream& operator<< (std::ostream& os, const Show& show)
{
    os << show.show();
    return os;
}

#include <tuple>
#include <vector>

// pretty-print a tuple (from http://stackoverflow.com/a/6245777/273767)
 
template<class Ch, class Tr, class Tuple, std::size_t... Is>
void _print_tuple_impl(std::basic_ostream<Ch,Tr>& os,
                      const Tuple & t,
                      std::index_sequence<Is...>)
{
    (void(os << (Is == 0 ? "" : ", ") << std::get<Is>(t)), ...);
}
 
template<class Ch, class Tr, class... Args>
decltype(auto) operator<<(std::basic_ostream<Ch, Tr>& os,
                          const std::tuple<Args...>& t)
{
    os << "(";
    _print_tuple_impl(os, t, std::index_sequence_for<Args...>{});
    return os << ")";
}

template <typename T>
std::ostream& operator<< (std::ostream& os, const std::vector<T>& vek)
{
    os << "[";
    if (!vek.empty())
    {
        size_t i = 0;
        for (i = 0; i < vek.size() - 1; ++i)
        {
            os << vek[i] << ", ";
        }
        os << vek[i];
    }
    os << "]";
    return os;
}

template <typename T, typename... Ts>
std::vector<T> make_vector(const T& head, const Ts&... tail)
{
    return std::vector<T>({head, tail...});
}
