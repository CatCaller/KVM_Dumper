#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace runtime_dumper {

struct ResourceRecovery {
    std::filesystem::path source;
    std::size_t bytes{};
    std::size_t pages{};
};

ResourceRecovery recover_file_backed_resources(std::vector<std::byte>& image,
                                               std::span<const std::size_t> page_bytes,
                                               std::size_t page_size,
                                               std::string_view image_name);

} // namespace runtime_dumper
