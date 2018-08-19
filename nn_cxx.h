// Author: lichao
// Date: 20180818

#ifndef _NN_CXX_H_INCLUDED
#define _NN_CXX_H_INCLUDED

#include <system_error>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <variant>
#include <atomic>
#include <mutex>

#include "nn.h"

namespace nn_cxx {

class error_category : public std::error_category {
public:
    const char *name() const noexcept override {
        return "nanomsg";
    }

    std::string message(int errnum) const override {
        return nn_strerror(errnum);
    }
};

inline const std::error_category& get_error_category() noexcept {
    static error_category s_error_category;
    return s_error_category;
}

inline void CheckError(bool ok, std::error_code& ec) noexcept {
    if (!ok) {
        ec.assign(nn_errno(), get_error_category());
    }
}

inline int CheckError(int ret, std::error_code& ec) noexcept {
    if (ret < 0) {
        ec.assign(nn_errno(), get_error_category());
    }

    return ret;
}

inline void ThrowError(const std::error_code& ec, const char *location) {
    if (ec) {
        throw std::system_error(ec, location);
    }
}

template<typename T, std::enable_if_t<std::is_move_constructible_v<T>, int> = 0>
constexpr T& MoveAssign(T *lhs, T&& rhs) {
    if (lhs != std::addressof(rhs)) {
        lhs->~T();
        new (lhs) T(std::move(rhs));
    }

    return *lhs;
}

class Msg {
public:
    Msg() noexcept = default;

    explicit Msg(size_t size, int type = 0) noexcept
        : data_(nn_allocmsg(size, type))
        , size_(size) {}

    ~Msg() {
        if (data_) {
            nn_freemsg(data_);
            data_ = nullptr;
            size_ = 0;
        }
    }

    Msg(Msg&& rhs) noexcept
        : data_(rhs.data_)
        , size_(rhs.size_) { 
        rhs.Detach();
    }

    Msg& operator=(Msg&& rhs) noexcept {
        return MoveAssign(this, std::move(rhs));
    }

    Msg(const Msg& rhs) = delete;
    void operator=(const Msg& rhs) = delete;

    void *data() noexcept { return data_; }
    void *data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }

    std::pair<void *, size_t> Detach() noexcept {
        return {
            std::exchange(data_, nullptr),
            std::exchange(size_, 0)
        };
    }

    void reset(void *data, size_t size) noexcept {
        this->~Msg();
        data_ = data;
        size_ = size;
    }
protected:
    void *data_ = nullptr;
    size_t size_ = 0;
};

enum class AF : int {
    SP = AF_SP,
    SP_RAW = AF_SP_RAW
};

const int kDONTWAIT = NN_DONTWAIT;

template<int Level, int Opt, typename T>
struct SocketOpt {
    T val;
};

using SndBufOpt = SocketOpt<NN_SOL_SOCKET, NN_SNDBUF, int>;
using RcvBufOpt = SocketOpt<NN_SOL_SOCKET, NN_RCVBUF, int>;
using SndTimeoutOpt = SocketOpt<NN_SOL_SOCKET, NN_SNDTIMEO, int>;
using RcvTimeoutOpt = SocketOpt<NN_SOL_SOCKET, NN_RCVTIMEO, int>;

class Socket {
public:
    static constexpr int kValidHandle = -1;

    Socket() noexcept = default;

    Socket(AF af, int protocol) {
        Create(af, protocol);
    }

    Socket(Socket&& rhs) noexcept : h_(rhs.Detach()) {}

    Socket& operator=(Socket&& rhs) noexcept {
        return MoveAssign(this, std::move(rhs));
    }

    ~Socket() {
        Close();
    }

    void Create(AF af, int protocol, std::error_code& ec) noexcept {
        Close(ec);
        if (ec) {
            return;
        }

        h_ = nn_socket(static_cast<int>(af), protocol);
        CheckError(Ok(), ec);
    }

    void Create(AF af, int protocol) {
        std::error_code ec;
        Create(af, protocol, ec);
        ThrowError(ec, "Socket.Create");
    }

    void Close(std::error_code& ec) noexcept {
        CheckError(!Ok() || (nn_close(Detach()) >= 0), ec);
    }

    void Close() {
        std::error_code ec;
        Close(ec);
        ThrowError(ec, "Socket.Close");
    }

    template<int Level, int Opt, typename T>
    void SetOpt(const SocketOpt<Level, Opt, T>& opt, std::error_code &ec) noexcept {
        CheckError(nn_setsockopt(h_, Level, Opt, &opt.val, sizeof opt.val), ec);
    }

    template<int Level, int Opt, typename T>
    void SetOpt(const SocketOpt<Level, Opt, T>& opt) {
        std::error_code ec;
        SetOpt(opt, ec);
        ThrowError(ec, "Socket.SetOpt");
    }

    template<int Level, int Opt, typename T>
    void GetOpt(SocketOpt<Level, Opt, T>& opt, std::error_code &ec) noexcept {
        size_t optvallen = sizeof opt.val;
        CheckError(nn_getsockopt(h_, Level, Opt, &opt.val, &optvallen), ec);
    }

    template<int Level, int Opt, typename T>
    void GetOpt(SocketOpt<Level, Opt, T>& opt) {
        std::error_code ec;
        GetOpt(opt, ec);
        ThrowError(ec, "Socket.GetOpt");
    }

    void Bind(const char *addr, std::error_code& ec) noexcept {
        CheckError(nn_bind(h_, addr), ec);
    }

    void Bind(const char *addr) {
        std::error_code ec;
        Bind(addr, ec);
        ThrowError(ec, "Socket.Bind");
    }

    void Connect(const char *addr, std::error_code& ec) noexcept {
        CheckError(nn_connect(h_, addr), ec);
    }

    void Connect(const char *addr) {
        std::error_code ec;
        Connect(addr, ec);
        ThrowError(ec, "Socket.Connect");
    }

    void Shutdown(int how, std::error_code& ec) noexcept {
        CheckError(nn_shutdown(h_, how), ec);
    }

    void Shutdown(int how) {
        std::error_code ec;
        Shutdown(how, ec);
        ThrowError(ec, "Socket.Shutdown");
    }

    int Send(const void *buf, size_t len, int flags, std::error_code &ec) noexcept {
        return CheckError(nn_send(h_, buf, len, flags), ec);
    }

    int Send(const void *buf, size_t len, int flags = 0) {
        std::error_code ec;
        int ret = Send(buf, len, flags, ec);
        ThrowError(ec, "Socket.Send");
        return ret;
    }

    int Recv(void *buf, size_t len, int flags, std::error_code &ec) noexcept {
        return CheckError(nn_recv(h_, buf, len, flags), ec);
    }

    int Recv(void **buf, int flags, std::error_code &ec) noexcept {
        return CheckError(nn_recv(h_, buf, NN_MSG, flags), ec);
    }

    int Recv(void *buf, size_t len, int flags = 0) {
        std::error_code ec;
        int ret = Recv(buf, len, flags, ec);
        ThrowError(ec, "Socket.Recv");
        return ret;
    }

    int Recv(void **buf, int flags = 0) {
        std::error_code ec;
        int ret = Recv(buf, flags, ec);
        ThrowError(ec, "Socket.Recv");
        return ret;
    }

    int Send(const Msg& msg, int flags, std::error_code &ec) noexcept {
        int ret = Send(msg.data(), static_cast<int>(msg.size()), flags, ec);
        if (ret > 0) {
            const_cast<Msg &>(msg).Detach();
        }
        return ret;
    }

    int Send(const Msg& msg, int flags = 0) {
        int ret = Send(msg.data(), static_cast<int>(msg.size()), flags);
        if (ret > 0) {
            const_cast<Msg &>(msg).Detach();
        }
        return ret;
    }

    void Recv(Msg &msg, int flags, std::error_code &ec) noexcept {
        void *buf = nullptr;
        int ret = Recv(&buf, flags, ec);
        if (ret > 0) {
            msg.reset(buf, ret);
        }
    }

    void Recv(Msg &msg, int flags = 0) {
        std::error_code ec;
        Recv(msg, flags, ec);
        ThrowError(ec, "Socket.Recv");
    }

    int fd() const noexcept { return h_; }
    bool Ok() const noexcept { return h_ >= 0; }
    operator bool() const noexcept { return Ok(); }
    int Detach() noexcept { return std::exchange(h_, kValidHandle); }
private:
    Socket(const Socket&) = delete;
    void operator=(const Socket&) = delete;

    int h_ = kValidHandle;
};

class SpinMutex {
public:
    bool try_lock() {
        return !flag_.test_and_set();
    }

    void lock() {
        while (flag_.test_and_set());
    }

    void unlock() {
        flag_.clear();
    }

private:
    std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

class Poller {
public:
    void AddSocket(int fd, std::function<void()> on_read, std::function<void()> on_write) {
        AddOp(fd, on_read, on_write);
    }

    void DelSocket(int fd, std::function<void()> on_close) {
        DelOp(fd, on_close);
    }

    int Poll(int timeout, std::error_code& ec) noexcept {
        CheckOp();

        int ret = nn_poll(fds_.data(), static_cast<int>(fds_.size()), timeout);
        if (ret <= 0) {
            return CheckError(ret, ec);
        }

        for (auto&& fd : fds_) {
            if (0 == fd.revents) {
                continue;
            }

            auto it = cbs_.find(fd.fd);
            if (it == cbs_.end()) {
                continue;
            }

            if ((NN_POLLIN & fd.revents) && it->second.first) {
                it->second.first();
            }

            if ((NN_POLLOUT & fd.revents) && it->second.second) {
                it->second.second();
            }

            fd.revents = 0;
        }

        return ret;
    }

    int Poll(int timeout) {
        std::error_code ec;
        int ret = Poll(timeout, ec);
        ThrowError(ec, "Poller.Poll");
        return ret;
    }
private:
    using Callback = std::pair<std::function<void()>, std::function<void()>>;
    using Op = std::variant<Callback, std::function<void()>>;

    void AddOp(int fd, std::function<void()> on_read, std::function<void()> on_write) {
        std::scoped_lock<SpinMutex> guard(mu_);
        ops_[fd].emplace<0>(on_read, on_write);
    }

    void DelOp(int fd, std::function<void()> on_close) {
        std::scoped_lock<SpinMutex> guard(mu_);
        ops_[fd].emplace<1>(on_close);
    }

    void CheckOp() {
        std::scoped_lock<SpinMutex> guard(mu_);
        for (auto&& op : ops_) {
            std::visit([this, fd = op.first](auto && arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, Callback>) {
                    AddFd(fd, arg);
                } else if constexpr (std::is_same_v<T, std::function<void()>>) {
                    DelFd(fd, arg);
                }
            }, op.second);
        }
        ops_.clear();
    }

    void AddFd(int fd, const Callback& cb) {
        auto it = std::find_if(fds_.begin(), fds_.end(), [&](const struct nn_pollfd& item) { return fd == item.fd; });
        if (it == fds_.end()) {
            fds_.emplace_back();
            it = fds_.end() - 1;
        }

        it->fd = fd;
        it->events = 0;
        it->revents = 0;

        if (cb.first) {
            it->events |= NN_POLLIN;
        }

        if (cb.second) {
            it->events |= NN_POLLOUT;
        }

        cbs_.insert_or_assign(fd, cb);
    }

    void DelFd(int fd, std::function<void()> on_close) {
        auto it = std::find_if(fds_.begin(), fds_.end(), [&](const struct nn_pollfd& item) { return fd == item.fd; });
        if (it != fds_.end()) {
            fds_.erase(it);
        }

        cbs_.erase(fd);

        on_close();
    }

    std::vector<struct nn_pollfd> fds_;
    std::unordered_map<int, Callback> cbs_;
    std::unordered_map<int, Op> ops_;
    SpinMutex mu_;
};

}
#endif // !_NN_CXX_H_INCLUDED