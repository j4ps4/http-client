#pragma once

#include "common.hpp"

#include <utility>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <type_traits>

enum IsErrorT {is_error};

template <typename T, typename E>
class Expected
{
public:
    Expected(const T& val) : ok_(true), value_(val) {}
    Expected(T&& val) : ok_(true), value_(std::move(val)) {}
    Expected() : ok_(false) {}
    Expected(const E& err, IsErrorT) : ok_(false), error_(err) {}
    Expected(E&& err, IsErrorT) : ok_(false), error_(std::move(err)) {}

    template <typename T2>
    Expected& operator= (T2&& value)
    {
        this->value_ = std::move(value);
        this->ok_ = true;
        return *this;
    }

    template <typename T2>
    Expected& operator= (const T2& value)
    {
        this->value_ = value;
        this->ok_ = true;
        return *this;
    }

    operator bool() const
    {
        return ok_;
    }

    const T& value() const&
    {
        if (ok_)
            return value_;
        else
        {
            if (std::is_base_of_v<Show, E>)
            {
                const char* msg = reinterpret_cast<const Show*>(&error_)->show();
                throw std::runtime_error(std::string("Expected::value(): got error: ")+msg);
            }
            else
                throw std::runtime_error("Expected::value(): got error");
        }
    }

    T& value() &
    {
        if (ok_)
            return value_;
        else
        {
            if (std::is_base_of_v<Show, E>)
            {
                const char* msg = reinterpret_cast<const Show*>(&error_)->show();
                throw std::runtime_error(std::string("Expected::value(): got error: ")+msg);
            }
            else
                throw std::runtime_error("Expected::value(): got error");
        }
    }

    T value() &&
    {
        return this->value();
    }

    E error() const
    {
        if (ok_)
            throw std::runtime_error("Expected::error(): is ok");
        else
            return error_;
    }

    T value_or(T val) const
    {
        if (ok_)
            return value_;
        else
            return val;
    }
    
    T value_or_failwith(const char* msg) const
    {
        if (ok_)
            return value_;
        else
            throw std::runtime_error(msg);
    }

    T value_or_failwith(std::function<const char*(const E&)>&& fun) const
    {
        if (ok_)
            return value_;
        else
            throw std::runtime_error(fun(error_));
    }

    template <typename UnaryOp>
    Expected<_UnResT, E> fmap(UnaryOp&& fun) const&
    {
        if (ok_)
        {
            return Expected<_UnResT, E>(fun(value_));
        }
        else
        {
            return Expected<_UnResT, E>(error_, is_error);
        }
    }

    template <typename UnaryOp>
    Expected<_UnResT, E> fmap(UnaryOp&& fun) &&
    {
        if (ok_)
        {
            return Expected<_UnResT, E>(fun(std::move(value_)));
        }
        else
        {
            return Expected<_UnResT, E>(std::move(error_), is_error);
        }
    }

    template<typename T1, typename E1>
    friend std::ostream& operator<< (std::ostream& os, const Expected<T1, E1>& exp);

private:
    bool ok_;
    T value_;
    E error_;
};


template <typename T1, typename E1>
Expected<T1,E1> unexpected(E1&& err)
{
    return Expected<T1, E1>(std::move(err), is_error);
}

template<typename BinaryOp, typename T, typename U, typename E>
Expected<_BinResT, E> liftA2(BinaryOp&& op, Expected<T,E>&& fst, Expected<U,E>&& snd)
{
    if (!fst)
        return unexpected<_BinResT>(fst.error());
    if (!snd)
        return unexpected<_BinResT>(snd.error());
    return op(fst.value(), snd.value());
}
