// Author: lichao
// Date: 20180818

#ifndef _NN_CXX_H_INCLUDED
#define _NN_CXX_H_INCLUDED

#include <system_error>
#include <memory>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <algorithm>
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

enum AF : int {
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

    Socket() = default;

    Socket(AF af, int protocol) {
        Create(af, protocol);
    }

    Socket(Socket&& other) : h_(other.Detach()) {}

    Socket& operator=(Socket&& other) noexcept {
        if (this != std::addressof(other)) {
            Close();
            h_ = other.Detach();
        }

        return *this;
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

    int native_handle() const noexcept { return h_; }
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

class Poller : public std::enable_shared_from_this<Poller> {
public:
    using Callback = std::function<void()>;

    [[nodiscard]]
    std::shared_ptr<Socket> AddSocket(AF af, int protocol, Callback on_read, Callback on_write) {
        auto socket = std::make_unique<Socket>(af, protocol);
        AddOp(socket->native_handle(), on_read, on_write);

        return {
            socket.release(),
            [sp = shared_from_this()](Socket *p) {
                sp->DelOp(p->Detach());
                delete p;
            }
        };
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
    void AddOp(int fd, Callback on_read, Callback on_write) {
        std::scoped_lock<SpinMutex> guard(mu_);
        ops_[fd].emplace(on_read, on_write);
    }

    void DelOp(int fd) {
        std::scoped_lock<SpinMutex> guard(mu_);
        ops_[fd].reset();
    }

    void CheckOp() {
        std::scoped_lock<SpinMutex> guard(mu_);
        for (auto&& op : ops_) {
            if (op.second.has_value()) {
                AddFd(op.first, op.second->first, op.second->second);
            } else {
                DelFd(op.first);
            }
        }
        ops_.clear();
    }

    void AddFd(int fd, Callback on_read, Callback on_write) {
        auto it = std::find_if(fds_.begin(), fds_.end(), [&](const struct nn_pollfd& item) { return fd == item.fd; });
        if (it == fds_.end()) {
            fds_.emplace_back();
            it = fds_.end() - 1;
        }

        it->fd = fd;
        it->events = 0;
        it->revents = 0;

        if (on_read) {
            it->events |= NN_POLLIN;
        }

        if (on_write) {
            it->events |= NN_POLLOUT;
        }

        cbs_.insert_or_assign(fd, std::make_pair(on_read, on_write));
    }

    void DelFd(int fd) {
        auto it = std::find_if(fds_.begin(), fds_.end(), [&](const struct nn_pollfd& item) { return fd == item.fd; });
        if (it != fds_.end()) {
            fds_.erase(it);
        }

        cbs_.erase(fd);

        nn_close(fd);
    }

    std::vector<struct nn_pollfd> fds_;
    std::unordered_map<int, std::pair<Callback, Callback>> cbs_;
    std::unordered_map<int, std::optional<std::pair<Callback, Callback>>> ops_;
    SpinMutex mu_;
};

}
#endif // !_NN_CXX_H_INCLUDED