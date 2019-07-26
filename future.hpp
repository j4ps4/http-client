#pragma once

#include "common.hpp"
#include "vector.hpp"

#include <pthread.h>
#include <functional>
#include <memory>
#include <stdexcept>
#include <vector>
#include <chrono>

namespace
{
    const pthread_t PTHREAD_MOVED = 0;
    const pthread_t PTHREAD_JOINED = -1;
    const pthread_t PTHREAD_FINISHED = -2;
    void join_error(std::string, int);
}

enum class FutureStatus
{
    Busy,
    Finished,
    Terminated
};

template <typename T>
class Future
{

    static void nul_cleanup_fn(void* arg)
    {
        delete (doNulOpArgs*)arg;
    }

    template<typename UnaryOp>
    static void un_cleanup_fn(void* arg)
    {
        delete (doUnOpArgs<UnaryOp>*)arg;
    }

    template<typename BinaryOp, typename T1>
    static void bin_cleanup_fn(void* arg)
    {
        delete (doBinOpArgs<BinaryOp, T1>*)arg;
    }

public:
    template <typename NullaryOp>
    explicit Future(NullaryOp&& fun)
    {
        auto args = new doNulOpArgs(std::move(fun));
        retval_ = std::make_shared<T>();
        args->retval_loc = retval_.get();
        pthread_create(&tid_, nullptr, doNulOp, args);
    }

    Future(Future<T>&& other) :
        retval_(std::move(other.retval_)),
        tid_(other.tid_),
        owned_(std::move(other.owned_))
    {
        other.tid_ = PTHREAD_MOVED;
    }

    // TODO needs private copy constructor

    Future() = default;

    FutureStatus wait_for(uint64_t seconds)
    {
        int i;
        FutureStatus out;
        int status;
        if (tid_ == PTHREAD_FINISHED)
            return FutureStatus::Finished;
        if (tid_ == PTHREAD_MOVED)
            return FutureStatus::Terminated;
        if (tid_ == PTHREAD_JOINED)
            return FutureStatus::Terminated;
        if (seconds > 0)
        {
            timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += seconds;
            status = pthread_timedjoin_np(tid_, nullptr, &ts);
        }
        else
        {
            status = pthread_tryjoin_np(tid_, nullptr);
        }
        switch (status)
        {
            case 0: {
                out = FutureStatus::Finished;
                tid_ = PTHREAD_FINISHED;
                return out;
            }
            case ETIMEDOUT:
            case EBUSY: {
                out = FutureStatus::Busy;
                return out;
            }
            default:
                join_error("Future::wait_for()", status);
        }
        // Not reached
        return FutureStatus::Terminated;
    }

    template <typename Rep, typename Period>
    FutureStatus wait_for(std::chrono::duration<Rep, Period> val)
    {
        FutureStatus out;
        int status;
        if (tid_ == PTHREAD_FINISHED)
            return FutureStatus::Finished;
        if (tid_ == PTHREAD_MOVED)
            return FutureStatus::Terminated;
        if (tid_ == PTHREAD_JOINED)
            return FutureStatus::Terminated;
        // is expressible in seconds?
        if (std::chrono::duration_cast<std::chrono::seconds>(val).count() > 0)
        {
            timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += std::chrono::duration_cast<std::chrono::seconds>(val).count();
            status = pthread_timedjoin_np(tid_, nullptr, &ts);
        }
        else if (std::chrono::duration_cast<std::chrono::nanoseconds>(val).count() > 0)
        {
            timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += std::chrono::duration_cast<std::chrono::nanoseconds>(val).count();
            status = pthread_timedjoin_np(tid_, nullptr, &ts);
        }
        else // duration zero
        {
            status = pthread_tryjoin_np(tid_, nullptr);
        }
        switch (status)
        {
            case 0: {
                out = FutureStatus::Finished;
                tid_ = PTHREAD_FINISHED;
                return out;
            }
            case ETIMEDOUT:
            case EBUSY: {
                out = FutureStatus::Busy;
                return out;
            }
            default:
                join_error("Future::wait_for()", status);
        }
        // Not reached
        return FutureStatus::Terminated;
    }

    T get()
    {
        // check if retval_ has value
        if (tid_ == PTHREAD_FINISHED)
        {
            T out(*retval_);
            retval_.reset();
            tid_ = PTHREAD_JOINED;
            return out;
        }
        if (tid_ == PTHREAD_MOVED)
            throw std::runtime_error("Future::get(): future moved");
        if (tid_ == PTHREAD_JOINED)
            throw std::runtime_error("Future::get(): thread joined");
        int join = pthread_join(tid_, nullptr);
        if (join)
            join_error("Future::get()", join);
        // if (rv == PTHREAD_CANCELED)
        //     throw std::runtime_error("Future::get(): thread canceled");
        T out(*retval_);
        retval_.reset();
        tid_ = PTHREAD_JOINED;
        return out;
    }
    template <typename UnaryOp>
    Future<_UnResT> fmap(UnaryOp&& fun)
    {
        return unaryConstr(std::move(fun), std::move(*this));
    }
    template <typename BinaryOp, typename U>
    Future<_BinResT> liftA2(BinaryOp&& fun, Future<U>&& snd)
    {
        return binaryConstr(std::move(fun), std::move(*this), std::move(snd));
    }
    ~Future()
    {
        // if thread has been joined or moved, do nothing
        if (tid_ == PTHREAD_JOINED || tid_ == PTHREAD_MOVED)
            return;
        for (pthread_t t : owned_)
            pthread_cancel(t);
        pthread_cancel(tid_);
    }

private:
    template <typename UnaryOp>
    static Future<_UnResT> unaryConstr(UnaryOp&& fun, Future<T>&& other)
    {
        if (other.tid_ == PTHREAD_MOVED)
            throw std::runtime_error("Future::fmap(): argument has been moved");
        if (other.tid_ == PTHREAD_JOINED)
            throw std::runtime_error("Future::fmap(): argument has been joined");
        Future<_UnResT> out;
        // out.arg1_ptr_ = std::make_shared<doUnOpArgs<UnaryOp1>>();
        auto args = new doUnOpArgs<UnaryOp>(std::move(fun));
        out.retval_ = std::make_shared<_UnResT>();
        // args->op = fun;
        args->other_retval = other.retval_; // to prevent other's retval from being destroyed
        args->tid_other = other.tid_;
        for (pthread_t t: other.owned_)
            out.owned_.push_back(t);
        out.owned_.push_back(other.tid_);
        other.tid_ = PTHREAD_MOVED;
        args->retval_loc = out.retval_.get();
        pthread_create(&out.tid_, nullptr, doUnOp<UnaryOp>, args);
        return out;
    }

    template <typename BinaryOp, typename U>
    static Future<_BinResT> binaryConstr(BinaryOp&& fun, Future<T>&& fst, Future<U>&& snd)
    {
        if (fst.tid_ == snd.tid_)
            throw std::runtime_error("Future::liftA2(): arguments cannot be equal");
        if (fst.tid_ == PTHREAD_MOVED || snd.tid_ == PTHREAD_MOVED)
            throw std::runtime_error("Future::liftA2(): argument has been moved");
        if (fst.tid_ == PTHREAD_JOINED || snd.tid_ == PTHREAD_JOINED)
            throw std::runtime_error("Future::liftA2(): argument has been joined");
        Future<_BinResT> out;
        auto args = new doBinOpArgs<BinaryOp, U>(std::move(fun));
        out.retval_ = std::make_shared<_BinResT>();
        // args->op = fun;
        args->fst_retval = fst.retval_; // to prevent other's retval from being destroyed
        args->snd_retval = snd.retval_; // to prevent other's retval from being destroyed
        args->tid_fst = fst.tid_;
        args->tid_snd = snd.tid_;
        for (pthread_t t: fst.owned_)
            out.owned_.push_back(t);
        for (pthread_t t: snd.owned_)
            out.owned_.push_back(t);
        out.owned_.push_back(fst.tid_);
        out.owned_.push_back(snd.tid_);
        fst.tid_ = PTHREAD_MOVED;
        snd.tid_ = PTHREAD_MOVED;
        args->retval_loc = out.retval_.get();
        pthread_create(&out.tid_, nullptr, doBinOp<BinaryOp, U>, args);
        return out;
    }

    struct doNulOpArgs
    {
        doNulOpArgs(std::function<T()>&& op_a) : op(op_a) {}
        std::function<T()> op;
        T* retval_loc;
    };

    template<typename UnaryOp>
    struct doUnOpArgs
    {
        doUnOpArgs(UnaryOp&& op_a) : op(op_a) {}
        UnaryOp op;
        std::shared_ptr<T> other_retval; // not used, just to keep reference count > 0
        pthread_t tid_other;
        _UnResT* retval_loc;
    };

    template<typename BinaryOp, typename U>
    struct doBinOpArgs
    {
        doBinOpArgs(BinaryOp&& op_a) : op(op_a) {}
        BinaryOp op;
        std::shared_ptr<T> fst_retval;
        std::shared_ptr<U> snd_retval;
        pthread_t tid_fst;
        pthread_t tid_snd;
        _BinResT* retval_loc;
    };

    static void* doNulOp(void* v_arg)
    {
        pthread_cleanup_push(nul_cleanup_fn, v_arg);
        doNulOpArgs* arg = (doNulOpArgs*)v_arg;
        T* rv_loc = arg->retval_loc;
        *rv_loc = arg->op();
        pthread_exit(rv_loc);
        pthread_cleanup_pop(0);
    }

    template<typename UnaryOp>
    static void* doUnOp(void* v_arg)
    {
        pthread_cleanup_push(un_cleanup_fn<UnaryOp>, v_arg);
        doUnOpArgs<UnaryOp>* arg = (doUnOpArgs<UnaryOp>*)v_arg;
        auto* rv_loc = arg->retval_loc;
        T* other_rv;
        int join = pthread_join(arg->tid_other, (void**) &other_rv);
        if (join)
            join_error("Future::fmap(): error joining", join);
        *rv_loc = arg->op(*other_rv);
        pthread_exit(rv_loc);
        pthread_cleanup_pop(0);
    }

    template<typename BinaryOp, typename U>
    static void* doBinOp(void* v_arg)
    {
        auto destr_ptr = bin_cleanup_fn<BinaryOp, U>;
        pthread_cleanup_push(destr_ptr, v_arg);
        doBinOpArgs<BinaryOp, U>* arg = (doBinOpArgs<BinaryOp, U>*)v_arg;
        auto* rv_loc = arg->retval_loc;
        T* fst_rv;
        U* snd_rv;
        int join = pthread_join(arg->tid_fst, (void**) &fst_rv);
        if (join)
            join_error("Future::liftA2(): error joining first thread", join);
        join = pthread_join(arg->tid_snd, (void**) &snd_rv);
        if (join)
            join_error("Future::liftA2(): error joining second thread", join);
        *rv_loc = arg->op(*fst_rv, *snd_rv);
        pthread_exit(rv_loc);
        pthread_cleanup_pop(0);
    }


public:

    std::shared_ptr<T> retval_;
    pthread_t tid_ = 0;
    std::vector<pthread_t> owned_;

};

template <typename Op, typename... Ts>
Future<_VarResT> make_future(Op&& op, Ts... args)
{
    return Future<_VarResT>([=](){return op(args...);});
}

// decltype(auto) preserves referenceness in return value
template <typename Op, typename... Ts>
_VarResT consume_future(Op&& op, Future<Ts>&&... args)
{
    return op(args.get()...);
}

template<typename T, typename UnaryOp>
Future<_UnResT> operator>> (Future<T>& rhs, UnaryOp&& op)
{
    return rhs.template fmap(op);
}

template<typename T, typename UnaryOp>
Future<_UnResT> operator>> (Future<T>&& rhs, UnaryOp&& op)
{
    return rhs.template fmap(op);
}

#define async(body) asyncc([&](){body})

template<typename NullaryOp>
Future<_NulRestT> asyncc(NullaryOp&& fun)
{
    return Future<_NulRestT>(std::move(fun));
}

template<typename BinaryOp, typename T, typename U>
Future<_BinResT> liftA2(BinaryOp&& fun, Future<T>&& fst, Future<U>&& snd)
{
    return fst.template liftA2(std::move(fun), std::move(snd));
}

template<typename T1, typename T2>
decltype(auto) operator+ (Future<T1>&& lhs, Future<T2>&& rhs)
{
    return liftA2([](T1 t1, T2 t2){return t1+t2;}, std::move(lhs), std::move(rhs));
}

template<typename T1, typename T2>
decltype(auto) operator- (Future<T1>&& lhs, Future<T2>&& rhs)
{
    return liftA2([](T1 t1, T2 t2){return t1-t2;}, std::move(lhs), std::move(rhs));
}

template<typename T1, typename T2>
decltype(auto) operator/ (Future<T1>&& lhs, Future<T2>&& rhs)
{
    return liftA2([](T1 t1, T2 t2){return t1/t2;}, std::move(lhs), std::move(rhs));
}

template<typename T1, typename T2>
decltype(auto) operator* (Future<T1>&& lhs, Future<T2>&& rhs)
{
    return liftA2([](T1 t1, T2 t2){return t1*t2;}, std::move(lhs), std::move(rhs));
}

namespace 
{
    void join_error(std::string lochelp, int errnum)
    {
        switch (errnum)
        {
            case EDEADLK:
                throw std::runtime_error(lochelp + ": deadlock detected");
            case EINVAL:
                throw std::runtime_error(lochelp + ": thread not joinable");
            case ESRCH:
                throw std::runtime_error(lochelp + ": no such thread");
            default:
                throw std::runtime_error(lochelp + ": unknown error number "+std::to_string(errnum));
        }
    }
}
