#include "qmp_freeze.h"

#include <cerrno>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace runtime_dumper {

std::string qmp_path_from_device(const std::string_view device) {
    const auto marker = device.find("qmp=");
    if (marker == std::string_view::npos) {
        return {};
    }

    const auto begin = marker + 4;
    const auto end = device.find(',', begin);

    return std::string{
        device.substr(begin, end == std::string_view::npos ? device.size() - begin : end - begin)};
}

QmpFreeze::QmpFreeze(std::string path) : path_(std::move(path)) {}

QmpFreeze::~QmpFreeze() {
    try {
        resume();
    } catch (...) {
    }

    if (socket_ >= 0) {
        ::close(socket_);
    }
}

std::string QmpFreeze::receive_reply(const bool reply_only) {
    for (;;) {
        if (const auto newline = buffered_.find('\n'); newline != std::string::npos) {
            auto line = buffered_.substr(0, newline);
            buffered_.erase(0, newline + 1);

            if (!reply_only || line.find("\"return\"") != std::string::npos
                || line.find("\"error\"") != std::string::npos) {
                return line;
            }

            continue;
        }

        pollfd descriptor{socket_, POLLIN, 0};
        const auto ready = ::poll(&descriptor, 1, 5000);

        if (!ready) {
            throw std::runtime_error("QMP reply timed out");
        }

        if (ready < 0) {
            throw std::runtime_error("QMP polling failed");
        }

        if (!(descriptor.revents & POLLIN)) {
            throw std::runtime_error("QMP socket closed");
        }

        char data[4096];
        const auto count = ::recv(socket_, data, sizeof(data), 0);

        if (count <= 0) {
            throw std::runtime_error("QMP socket read failed");
        }

        buffered_.append(data, static_cast<std::size_t>(count));
    }
}

std::string QmpFreeze::transact(const std::string_view command) {
    std::string request{command};
    request.push_back('\n');

    std::size_t sent{};

    while (sent < request.size()) {
        const auto count =
            ::send(socket_, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (count <= 0) {
            throw std::runtime_error("QMP socket write failed");
        }

        sent += static_cast<std::size_t>(count);
    }

    auto reply = receive_reply();

    if (reply.find("\"error\"") != std::string::npos) {
        throw std::runtime_error("QMP command failed: " + reply);
    }

    return reply;
}

void QmpFreeze::freeze() {
    if (frozen_) {
        return;
    }
    if (path_.empty()) {
        throw std::runtime_error("a QMP socket is required for a consistent image capture");
    }

    socket_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_ < 0) {
        throw std::runtime_error("unable to create QMP socket");
    }

    sockaddr_un address{};
    address.sun_family = AF_UNIX;

    if (path_.size() >= sizeof(address.sun_path)) {
        throw std::runtime_error("QMP socket path is too long");
    }

    std::memcpy(address.sun_path, path_.c_str(), path_.size() + 1);

    if (::connect(socket_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        throw std::runtime_error("unable to connect to QMP socket " + path_ + ": "
                                 + std::strerror(errno));
    }

    const auto greeting = receive_reply(false);

    if (greeting.find("\"QMP\"") == std::string::npos) {
        throw std::runtime_error("invalid QMP greeting");
    }

    static_cast<void>(transact(R"({"execute":"qmp_capabilities"})"));
    const auto status = transact(R"({"execute":"query-status"})");
    was_running_ = status.find("\"running\":true") != std::string::npos;

    if (was_running_) {
        static_cast<void>(transact(R"({"execute":"stop"})"));
    }

    frozen_ = true;
}

void QmpFreeze::resume() {
    if (!frozen_) {
        return;
    }

    if (was_running_) {
        static_cast<void>(transact(R"({"execute":"cont"})"));
    }

    frozen_ = false;
}

} // namespace runtime_dumper
