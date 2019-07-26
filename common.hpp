#pragma once

#include <string_view>
#include <utility>
#include <ostream>
#include <functional>

class Show
{
public:
    virtual const char* show() const = 0;
    virtual ~Show() = default;
};

template <class T>
constexpr std::string_view type_name()
{
    using namespace std;
#ifdef __clang__
    string_view p = __PRETTY_FUNCTION__;
    return string_view(p.data() + 34, p.size() - 34 - 1);
#elif defined(__GNUC__)
    string_view p = __PRETTY_FUNCTION__;
#  if __cplusplus < 201402
    return string_view(p.data() + 36, p.size() - 36 - 1);
#  else
    return string_view(p.data() + 56, p.find(';', 49) - 56);
#  endif
#elif defined(_MSC_VER)
    string_view p = __FUNCSIG__;
    return string_view(p.data() + 84, p.size() - 84 - 7);
#endif
}

// "Macro for each" adapted from https://codecraft.co/2014/11/25/variadic-macros-tricks/ 
// Accept any number of args >= N, but expand to just the Nth one.
// Here, N == 24.
#define _GET_NTH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, \
    _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
    _21, _22, _23, N, ...) N

// Define some macros to help us create overrides based on the
// arity of a for-each-style macro.
#define _fe_0(_call, ...)
#define _fe_1(_call, x) _call(x)
#define _fe_2(_call, x, ...) _call(x), _fe_1(_call, __VA_ARGS__)
#define _fe_3(_call, x, ...) _call(x), _fe_2(_call, __VA_ARGS__)
#define _fe_4(_call, x, ...) _call(x), _fe_3(_call, __VA_ARGS__)
#define _fe_5(_call, x, ...) _call(x), _fe_4(_call, __VA_ARGS__)
#define _fe_6(_call, x, ...) _call(x), _fe_5(_call, __VA_ARGS__)
#define _fe_7(_call, x, ...) _call(x), _fe_6(_call, __VA_ARGS__)
#define _fe_8(_call, x, ...) _call(x), _fe_7(_call, __VA_ARGS__)
#define _fe_9(_call, x, ...) _call(x), _fe_8(_call, __VA_ARGS__)
#define _fe_10(_call, x, ...) _call(x), _fe_9(_call, __VA_ARGS__)
#define _fe_11(_call, x, ...) _call(x), _fe_10(_call, __VA_ARGS__)
#define _fe_12(_call, x, ...) _call(x), _fe_11(_call, __VA_ARGS__)
#define _fe_13(_call, x, ...) _call(x), _fe_12(_call, __VA_ARGS__)
#define _fe_14(_call, x, ...) _call(x), _fe_13(_call, __VA_ARGS__)
#define _fe_15(_call, x, ...) _call(x), _fe_14(_call, __VA_ARGS__)
#define _fe_16(_call, x, ...) _call(x), _fe_15(_call, __VA_ARGS__)
#define _fe_17(_call, x, ...) _call(x), _fe_16(_call, __VA_ARGS__)
#define _fe_18(_call, x, ...) _call(x), _fe_17(_call, __VA_ARGS__)
#define _fe_19(_call, x, ...) _call(x), _fe_18(_call, __VA_ARGS__)
#define _fe_20(_call, x, ...) _call(x), _fe_19(_call, __VA_ARGS__)
#define _fe_21(_call, x, ...) _call(x), _fe_20(_call, __VA_ARGS__)
#define _fe_22(_call, x, ...) _call(x), _fe_21(_call, __VA_ARGS__)

/**
 * Provide a for-each construct for variadic macros. Supports up
 * to 22 args.
 */
#define CALL_MACRO_X_FOR_EACH(x, ...) \
    _GET_NTH_ARG("ignored", ##__VA_ARGS__, \
_fe_22, _fe_21, _fe_20, _fe_19, _fe_18, _fe_17, _fe_16, _fe_15, \
_fe_14, _fe_13, _fe_12, _fe_11, _fe_10, _fe_9, _fe_8, \
_fe_7, _fe_6, _fe_5, _fe_4, _fe_3, _fe_2, _fe_1, _fe_0)(x, ##__VA_ARGS__)

#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define PP_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

// Calculates return type of function.
#define _NulRestT std::invoke_result_t<NullaryOp>
#define _UnResT std::invoke_result_t<UnaryOp, T>
#define _BinResT std::invoke_result_t<BinaryOp, T, U>
#define _VarResT std::invoke_result_t<Op, Ts...>
#define _VarResT1 std::invoke_result_t<Op, T, Ts...>

#define _DATA_FIELD(x) #x, data.x

#define _MAKER_IMPL(Type) template <typename... Ts> \
Type _##Type##_maker_impl(const Ts&... args) \
{ \
    return Type(args...); \
}

// Generic printing for structs.
#define define_printer(Type, ...) std::ostream& operator<<(std::ostream& os, const Type& data) \
{ \
    os << #Type "("; \
    _print_loop<PP_NARG(__VA_ARGS__)*2>::_print_impl(os, CALL_MACRO_X_FOR_EACH(_DATA_FIELD, ##__VA_ARGS__)); \
    os << ")"; \
    return os; \
}

// Generic constructor function.
#define define_maker(Type, ...) _MAKER_IMPL(Type) auto Type##_ = &_##Type##_maker_impl<__VA_ARGS__>;

template <int I>
struct _print_loop
{
    template <typename U, typename... Ts>
    static void _print_impl(std::ostream& os, const char* fname, const U& fvalue, const Ts&... rest)
    {
        os << fname << ": " << fvalue << ", ";
        _print_loop<sizeof...(rest)>::_print_impl(os, rest...);
    }
};

template <>
struct _print_loop<2>
{
    template <typename U>
    static void _print_impl(std::ostream&os, const char* fname, const U& fvalue)
    {
        os << fname << ": " << fvalue;
    }
};

// Identity function.
template <typename T>
struct id
{
    T operator()(const T& t) const {return t;}
};

//! Metafunction invocation
template <typename T>
using Invoke = typename T::type;

//! Meta-boolean type with parameters for when dependent contexts are needed
template <bool B, typename...>
struct dependent_bool_type : std::integral_constant<bool, B> {};

//! Boolean integral_constant alias
template <bool B, typename... T>
using Bool = Invoke<dependent_bool_type<B, T...>>;

//! Tests if T is a specialization of Template
template <typename T, template <typename...> class Template>
struct is_specialization_of : Bool<false> {};

template <template <typename...> class Template, typename... Args>
struct is_specialization_of<Template<Args...>, Template> : Bool<true> {};

