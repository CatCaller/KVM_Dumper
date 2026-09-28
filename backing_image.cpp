#include "backing_image.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace runtime_dumper {
namespace {

template <typename T>
T read_value(const std::span<const std::byte> bytes, const std::size_t offset) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::runtime_error("truncated backing PE");
    }

    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));

    return value;
}

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });

    return value;
}

struct Section {
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_address{};
    std::uint32_t raw_size{};
    std::uint32_t characteristics{};
};

struct PeLayout {
    std::uint32_t timestamp{};
    std::uint32_t image_size{};
    std::uint32_t resource_rva{};
    std::uint32_t resource_size{};
    std::vector<Section> sections;
};

struct RawRange {
    std::uint32_t rva{};
    std::size_t size{};
};

struct ResourceIdentifier {
    std::uint32_t root{};
    std::uint32_t value{};
};

PeLayout parse_layout(const std::span<const std::byte> bytes) {
    if (read_value<std::uint16_t>(bytes, 0) != 0x5a4d) {
        throw std::runtime_error("invalid backing DOS header");
    }

    const auto nt = static_cast<std::size_t>(read_value<std::uint32_t>(bytes, 0x3c));
    if (read_value<std::uint32_t>(bytes, nt) != 0x00004550) {
        throw std::runtime_error("invalid backing NT header");
    }

    const auto section_count = read_value<std::uint16_t>(bytes, nt + 6);
    const auto optional_size = read_value<std::uint16_t>(bytes, nt + 20);
    const auto optional = nt + 24;
    const auto magic = read_value<std::uint16_t>(bytes, optional);
    const auto directories = optional + (magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0);
    if (!directories || section_count > 96 || optional_size < directories - optional + 24) {
        throw std::runtime_error("invalid backing optional header");
    }

    PeLayout result{read_value<std::uint32_t>(bytes, nt + 8),
                    read_value<std::uint32_t>(bytes, optional + 56),
                    read_value<std::uint32_t>(bytes, directories + 16),
                    read_value<std::uint32_t>(bytes, directories + 20),
                    {}};
    const auto table = optional + optional_size;
    result.sections.reserve(section_count);

    for (std::uint16_t index{}; index < section_count; ++index) {
        const auto offset = table + static_cast<std::size_t>(index) * 40;
        result.sections.push_back({read_value<std::uint32_t>(bytes, offset + 12),
                                   read_value<std::uint32_t>(bytes, offset + 8),
                                   read_value<std::uint32_t>(bytes, offset + 20),
                                   read_value<std::uint32_t>(bytes, offset + 16),
                                   read_value<std::uint32_t>(bytes, offset + 36)});
    }

    if (!result.resource_rva || !result.resource_size) {
        throw std::runtime_error("backing PE has no resources");
    }

    return result;
}

std::optional<std::size_t> raw_offset(const PeLayout& layout, const RawRange range) {
    for (const auto& section : layout.sections) {
        if (range.rva < section.virtual_address) {
            continue;
        }

        const auto relative = static_cast<std::size_t>(range.rva - section.virtual_address);

        if (relative <= section.raw_size && range.size <= section.raw_size - relative) {
            return section.raw_address + relative;
        }
    }

    return std::nullopt;
}

struct ResourceLeaf {
    std::uint32_t rva{};
    std::uint32_t size{};
    std::uint32_t codepage{};
};

using ResourceMap = std::map<std::string, ResourceLeaf>;
using View = std::function<std::optional<std::span<const std::byte>>(std::uint32_t, std::size_t)>;

std::string resource_name(const View& view, const ResourceIdentifier identifier) {
    if (!(identifier.value & 0x80000000)) {
        return "#" + std::to_string(identifier.value);
    }

    const auto offset = identifier.value & 0x7fffffff;
    const auto header = view(identifier.root + offset, 2);
    if (!header) {
        throw std::runtime_error("invalid resource name");
    }

    const auto length = read_value<std::uint16_t>(*header, 0);
    const auto bytes = view(identifier.root + offset + 2, static_cast<std::size_t>(length) * 2);
    if (!bytes) {
        throw std::runtime_error("truncated resource name");
    }

    std::string result{"@"};

    for (std::uint16_t index{}; index < length; ++index) {
        result +=
            std::to_string(read_value<std::uint16_t>(*bytes, static_cast<std::size_t>(index) * 2))
            + ".";
    }

    return result;
}

ResourceMap resources(const PeLayout& layout, const View& view) {
    ResourceMap result;
    std::set<std::pair<std::uint32_t, std::size_t>> visited;
    const auto walk = [&](const auto& self,
                          const std::uint32_t table,
                          const std::string& path,
                          const std::size_t depth) -> void {
        if (depth > 8 || !visited.emplace(table, depth).second) {
            throw std::runtime_error("invalid resource tree");
        }

        const auto header = view(layout.resource_rva + table, 16);
        if (!header) {
            throw std::runtime_error("truncated resource directory");
        }

        const auto count = static_cast<std::size_t>(read_value<std::uint16_t>(*header, 12))
            + read_value<std::uint16_t>(*header, 14);

        if (count > 4096) {
            throw std::runtime_error("oversized resource directory");
        }

        const auto entries = view(layout.resource_rva + table + 16, count * 8);
        if (!entries) {
            throw std::runtime_error("truncated resource entries");
        }

        for (std::size_t index{}; index < count; ++index) {
            const auto name = read_value<std::uint32_t>(*entries, index * 8);
            const auto value = read_value<std::uint32_t>(*entries, index * 8 + 4);
            const auto key = path + "/" + resource_name(view, {layout.resource_rva, name});

            if (value & 0x80000000) {
                self(self, value & 0x7fffffff, key, depth + 1);
                continue;
            }

            const auto entry = view(layout.resource_rva + value, 16);
            if (!entry || result.size() == 16384) {
                throw std::runtime_error("invalid resource data entry");
            }

            if (!result
                     .emplace(key,
                              ResourceLeaf{read_value<std::uint32_t>(*entry, 0),
                                           read_value<std::uint32_t>(*entry, 4),
                                           read_value<std::uint32_t>(*entry, 8)})
                     .second) {
                throw std::runtime_error("duplicate resource path");
            }
        }
    };

    walk(walk, 0, {}, 0);

    return result;
}

std::vector<std::byte> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }

    const auto end = file.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > std::numeric_limits<std::size_t>::max()) {
        return {};
    }

    std::vector<std::byte> result(static_cast<std::size_t>(end));
    file.seekg(0);
    file.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));

    return file ? std::move(result) : std::vector<std::byte>{};
}

std::vector<std::filesystem::path> candidates(const std::string_view image_name) {
    std::vector<std::filesystem::path> result;
    if (const auto configured = std::getenv("RUNTIME_DUMPER_IMAGE"); configured && *configured) {
        result.emplace_back(configured);
    }

    const auto expected = lower(std::filesystem::path(image_name).filename().string());
    std::error_code error;

    for (const std::filesystem::path root : {"/mnt/source", "/mnt/games"}) {
        if (!std::filesystem::is_directory(root, error)) {
            continue;
        }

        std::filesystem::recursive_directory_iterator iterator(
            root, std::filesystem::directory_options::skip_permission_denied, error);
        const std::filesystem::recursive_directory_iterator end;

        while (!error && iterator != end) {
            if (iterator->is_regular_file(error)
                && lower(iterator->path().filename().string()) == expected) {
                result.push_back(iterator->path());
            }
            iterator.increment(error);
        }

        error.clear();
    }

    return result;
}

ResourceRecovery recover_from(std::vector<std::byte>& image,
                              const std::span<const std::size_t> page_bytes,
                              const std::size_t page_size,
                              const std::filesystem::path& path) {
    const auto source = read_file(path);
    if (source.empty()) {
        return {};
    }

    const auto memory_layout = parse_layout(image);
    const auto source_layout = parse_layout(source);

    if (memory_layout.timestamp != source_layout.timestamp
        || memory_layout.image_size != source_layout.image_size
        || memory_layout.sections.size() != source_layout.sections.size()) {
        return {};
    }

    for (std::size_t index{}; index < memory_layout.sections.size(); ++index) {
        const auto& memory_section = memory_layout.sections[index];
        const auto& source_section = source_layout.sections[index];
        if (memory_section.virtual_address != source_section.virtual_address
            || memory_section.virtual_size != source_section.virtual_size
            || memory_section.characteristics != source_section.characteristics) {
            return {};
        }
    }

    const View memory_view =
        [&](const std::uint32_t rva,
            const std::size_t size) -> std::optional<std::span<const std::byte>> {
        if (rva > image.size() || size > image.size() - rva) {
            return std::nullopt;
        }
        return std::span<const std::byte>{image}.subspan(rva, size);
    };

    const View source_view =
        [&](const std::uint32_t rva,
            const std::size_t size) -> std::optional<std::span<const std::byte>> {
        const auto offset = raw_offset(source_layout, {rva, size});
        if (!offset || *offset > source.size() || size > source.size() - *offset) {
            return std::nullopt;
        }
        return std::span<const std::byte>{source}.subspan(*offset, size);
    };

    const auto memory_resources = resources(memory_layout, memory_view);
    const auto source_resources = resources(source_layout, source_view);

    if (memory_resources.size() != source_resources.size()) {
        return {};
    }

    for (const auto& [key, destination] : memory_resources) {
        const auto found = source_resources.find(key);
        if (found == source_resources.end() || found->second.size != destination.size
            || found->second.codepage != destination.codepage) {
            return {};
        }
    }

    ResourceRecovery result{path, 0, 0};
    std::set<std::size_t> recovered_pages;

    for (const auto& [key, destination] : memory_resources) {
        const auto& source_entry = source_resources.at(key);
        const auto source_data = source_view(source_entry.rva, source_entry.size);
        if (!source_data || destination.rva > image.size()
            || destination.size > image.size() - destination.rva) {
            continue;
        }

        for (std::size_t offset{}; offset < destination.size; ++offset) {
            const auto image_offset = static_cast<std::size_t>(destination.rva) + offset;
            const auto page = image_offset / page_size;
            const auto within = image_offset % page_size;
            if (page >= page_bytes.size() || within < page_bytes[page]) {
                continue;
            }

            image[image_offset] = (*source_data)[offset];
            ++result.bytes;
            recovered_pages.insert(page);
        }
    }

    result.pages = recovered_pages.size();

    return result;
}

} // namespace

ResourceRecovery recover_file_backed_resources(std::vector<std::byte>& image,
                                               const std::span<const std::size_t> page_bytes,
                                               const std::size_t page_size,
                                               const std::string_view image_name) {
    if (!page_size || page_bytes.size() != (image.size() + page_size - 1) / page_size) {
        return {};
    }

    for (const auto& path : candidates(image_name)) {
        try {
            auto result = recover_from(image, page_bytes, page_size, path);
            if (result.bytes) {
                return result;
            }
        } catch (const std::exception&) {
            continue;
        }
    }

    return {};
}

} // namespace runtime_dumper
