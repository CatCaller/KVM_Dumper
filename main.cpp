#include "runtime_dump.h"

#include <charconv>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string_view>

int main(const int count, char** values) {
    if (count != 2 && count != 3) {
        std::cerr << "usage: sudo ./dump <process-name> | sudo ./dump --pid <pid>\n";
        return 2;
    }

    try {
        if (count == 2) {
            return runtime_dumper::run(std::string_view{values[1]});
        }

        if (std::string_view{values[1]} != "--pid") {
            std::cerr << "usage: sudo ./dump <process-name> | sudo ./dump --pid <pid>\n";
            return 2;
        }

        std::uint32_t process_id{};
        const std::string_view value{values[2]};
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), process_id);

        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !process_id) {
            std::cerr << "invalid PID\n";
            return 2;
        }

        return runtime_dumper::run(process_id);
    } catch (const std::exception& error) {
        std::cerr << "dump: " << error.what() << '\n';
        return 1;
    }
}
