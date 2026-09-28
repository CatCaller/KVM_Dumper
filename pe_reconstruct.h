#pragma once

#include <kvmlib/kvmlib.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace runtime_dumper {

struct Import {
    std::uint32_t slot{};
    std::uint32_t ordinal{};
    std::string name;
};

struct ImportGroup {
    std::string module;
    std::vector<Import> imports;
};

struct Reconstruction {
    std::vector<std::byte> file;
    std::size_t imports{};
    std::size_t import_groups{};
    std::size_t recovered_imports{};
    std::string relocation_status;
    std::size_t exception_entries{};
    std::size_t dropped_exception_entries{};
};

struct ImageInfo {
    std::uint32_t image_size{};
    std::uint32_t headers_size{};
    std::uint32_t entry{};
    std::uint64_t image_base{};
    bool is_64{};
    struct Section {
        std::string name;
        std::uint32_t virtual_address{};
        std::uint32_t virtual_size{};
        std::uint32_t raw_size{};
        std::uint32_t characteristics{};
    };
    std::vector<Section> sections;
    struct Directory {
        std::uint32_t virtual_address{};
        std::uint32_t size{};
    };
    std::vector<Directory> directories;
};

ImageInfo inspect_pe_image(std::span<const std::byte> image);

std::vector<ImportGroup> recover_imports(std::span<const std::byte> image,
                                         std::uint64_t runtime_base,
                                         kvmlib::MemProcFs& memory,
                                         std::uint32_t process_id,
                                         std::span<const kvmlib::ModuleInfo> modules,
                                         std::uint64_t excluded_base,
                                         std::size_t& recovered_count);

Reconstruction reconstruct_pe(std::vector<std::byte> image,
                              std::uint64_t runtime_base,
                              std::uint64_t module_entry,
                              const std::vector<ImportGroup>& imports,
                              std::size_t recovered_imports);

void validate_pe_file(std::span<const std::byte> file);

} // namespace runtime_dumper
