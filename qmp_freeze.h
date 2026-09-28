#pragma once

#include <string>
#include <string_view>

namespace runtime_dumper {

std::string qmp_path_from_device(std::string_view device);

class QmpFreeze {
  public:
    explicit QmpFreeze(std::string path);
    ~QmpFreeze();
    QmpFreeze(const QmpFreeze&) = delete;
    QmpFreeze& operator=(const QmpFreeze&) = delete;

    void freeze();
    void resume();
    [[nodiscard]] bool active() const noexcept {
        return frozen_;
    }

  private:
    std::string transact(std::string_view command);
    std::string receive_reply(bool reply_only = true);

    std::string path_;
    int socket_{-1};
    bool was_running_{};
    bool frozen_{};
    std::string buffered_;
};

} // namespace runtime_dumper
