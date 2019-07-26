#pragma once

#define VECTOR 1

#include "common.hpp"

#include <vector>
#include <iostream>
#include <algorithm>
#include <functional>
#include <tuple>

template <typename T>
class Vector;

namespace 
{
    template <int I>
    struct loop
    {
        template <typename Op, typename Vec, typename... Vs, typename H, typename... Hs>
        static void push_back(Op&& op, Vec& vek, const std::tuple<Vs...>& loop_args, const Vector<H>& head, const Vector<Hs>&... rest)
        {
            std::for_each(head.cbegin(), head.cend(), [&](const auto& val){
                auto new_args = std::tuple_cat(loop_args, std::make_tuple(val));
                loop<sizeof...(rest)>::push_back(op, vek, new_args, rest...);
            });
        }
    };

    template<>
    struct loop<0>
    {
        template <typename Op, typename Vec, typename... Vs>
        static void push_back(Op&& op, Vec& vek, const std::tuple<Vs...>& loop_args)
        {
            vek.push_back(std::apply(op, loop_args));
        }
    };
}

template <typename T>
class Vector: public std::vector<T>
{
public:
    Vector(std::initializer_list<T>&& vals) : std::vector<T>(std::move(vals)) {}
    Vector(size_t size) : std::vector<T>(size) {}
    Vector() : std::vector<T>() {}
    Vector(const std::vector<T>& other) : std::vector<T>(other) {}
    Vector(std::vector<T>&& other) : std::vector<T>(std::move(other)) {}
    Vector(const Vector<T>& other) : std::vector<T>(other) {}
    Vector(Vector<T>&& other) : std::vector<T>(std::move(other)) {}

    template<typename UnaryOp>
    Vector<_UnResT> fmap(UnaryOp op) const
    {
        Vector<_UnResT> out(this->size());
        std::transform(this->cbegin(), this->cend(), out.begin(), op);
        return out;
    }

    template<typename UnaryOp>
    Vector<_UnResT> mapM(UnaryOp op)
    {
        Vector<_UnResT> out(this->size());
        std::transform(this->begin(), this->end(), out.begin(), op);
        return out;
    }

    template<typename Op, typename... Ts>
    Vector<_VarResT1> alift(Op&& op, const Vector<Ts>&... args) const
    {
        Vector<_VarResT1> out((this->size() * ... * args.size()));
        out.clear();
        std::for_each(this->cbegin(), this->cend(), [&](const auto& val){
            auto loop_args = std::make_tuple(val);
            loop<sizeof...(args)>::push_back(op, out, loop_args, args...);
        });
        return out;
    }

    static Vector<T> pure(const T& val)
    {
        return Vector<T>{val};
    }

    template<typename UnaryOp>
    _UnResT mbind(UnaryOp&& op) const
    {
        _UnResT out;
        std::for_each(this->cbegin(), this->cend(), [&](const T& val) {
            _UnResT temp = op(val);
            std::copy(temp.begin(), temp.end(), std::back_inserter(out));
        });
        return out;
    }

};

template<typename Op, typename T, typename... Ts>
Vector<_VarResT1> alift(Op&& op, const Vector<T>& head, const Vector<Ts>&... rest)
{
    return head.template alift(op, rest...);
}

template<typename UnaryOp, typename T>
_UnResT mbind(UnaryOp&& op, const Vector<T>& arg)
{
    return arg.template mbind(op);
}


template<typename UnaryOp, typename T>
Vector<_UnResT> operator>> (const Vector<T>& rhs, UnaryOp&& op)
{
    return rhs.template fmap(op);
}

template<typename UnaryOp, typename T>
_UnResT operator>>= (const Vector<T>& lhs, UnaryOp&& op)
{
    return lhs.template mbind(op);
}
