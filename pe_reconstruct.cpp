#include "pe_reconstruct.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <iostream>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace runtime_dumper {
namespace {

constexpr std::uint32_t pe32_magic = 0x10b;
constexpr std::uint32_t pe64_magic = 0x20b;
constexpr std::uint32_t section_code = 0x00000020;
constexpr std::uint32_t section_initialized = 0x00000040;
constexpr std::uint32_t section_uninitialized = 0x00000080;
constexpr std::uint32_t section_executable = 0x20000000;
constexpr std::uint32_t section_readable = 0x40000000;
constexpr std::uint32_t section_writable = 0x80000000;
constexpr std::uint16_t relocs_stripped = 0x0001;
constexpr std::uint16_t dynamic_base = 0x0040;
constexpr std::uint16_t high_entropy_va = 0x0020;

template <typename T>
T read_value(const std::span<const std::byte> bytes, const std::size_t offset) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::runtime_error("truncated PE image");
    }

    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(value));

    return value;
}

template <typename T>
void write_value(const std::span<std::byte> bytes, const std::size_t offset, const T value) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        throw std::runtime_error("truncated PE image");
    }

    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

bool power_of_two(const std::uint32_t value) {
    return value && !(value & (value - 1));
}

std::uint32_t align_up(const std::uint32_t value, const std::uint32_t alignment) {
    if (!power_of_two(alignment)
        || value > std::numeric_limits<std::uint32_t>::max() - (alignment - 1)) {
        throw std::runtime_error("invalid PE alignment");
    }

    return (value + alignment - 1) & ~(alignment - 1);
}

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });

    return value;
}

std::string base_name(const std::string_view value) {
    const auto separator = value.find_last_of("/\\");

    return std::string{value.substr(separator == std::string_view::npos ? 0 : separator + 1)};
}

struct Section {
    std::size_t header{};
    std::string name;
    std::uint32_t virtual_size{};
    std::uint32_t virtual_address{};
    std::uint32_t raw_size{};
    std::uint32_t raw_address{};
    std::uint32_t characteristics{};
};

struct Pe {
    std::size_t nt{};
    std::size_t optional{};
    std::size_t directories{};
    std::size_t sections_offset{};
    std::uint16_t section_count{};
    std::uint16_t optional_size{};
    std::uint16_t magic{};
    std::uint32_t entry{};
    std::uint64_t image_base{};
    std::uint32_t section_alignment{};
    std::uint32_t file_alignment{};
    std::uint32_t image_size{};
    std::uint32_t headers_size{};
    std::uint32_t directory_count{};
    std::vector<Section> sections;

    bool is_64() const noexcept {
        return magic == pe64_magic;
    }

    std::pair<std::uint32_t, std::uint32_t> directory(const std::span<const std::byte> bytes,
                                                      const std::size_t index) const {
        if (index >= directory_count) {
            return {};
        }

        const auto offset = directories + index * 8;

        if (offset + 8 > optional + optional_size) {
            return {};
        }

        return {read_value<std::uint32_t>(bytes, offset),
                read_value<std::uint32_t>(bytes, offset + 4)};
    }
};

Pe parse_pe(const std::span<const std::byte> bytes) {
    if (bytes.size() < 0x40 || read_value<std::uint16_t>(bytes, 0) != 0x5a4d) {
        throw std::runtime_error("missing DOS signature");
    }

    Pe pe;
    pe.nt = read_value<std::uint32_t>(bytes, 0x3c);

    if (pe.nt > bytes.size() - 24 || read_value<std::uint32_t>(bytes, pe.nt) != 0x00004550) {
        throw std::runtime_error("missing PE signature");
    }

    pe.section_count = read_value<std::uint16_t>(bytes, pe.nt + 6);
    pe.optional_size = read_value<std::uint16_t>(bytes, pe.nt + 20);
    pe.optional = pe.nt + 24;
    if (pe.optional_size > bytes.size() - pe.optional) {
        throw std::runtime_error("truncated optional header");
    }

    pe.magic = read_value<std::uint16_t>(bytes, pe.optional);

    if (pe.magic != pe64_magic && pe.magic != pe32_magic) {
        throw std::runtime_error("unsupported PE format");
    }

    const auto minimum_optional = pe.is_64() ? 112u : 96u;

    if (pe.optional_size < minimum_optional) {
        throw std::runtime_error("optional header is too small");
    }

    pe.entry = read_value<std::uint32_t>(bytes, pe.optional + 16);
    pe.image_base = pe.is_64() ? read_value<std::uint64_t>(bytes, pe.optional + 24)
                               : read_value<std::uint32_t>(bytes, pe.optional + 28);
    pe.section_alignment = read_value<std::uint32_t>(bytes, pe.optional + 32);
    pe.file_alignment = read_value<std::uint32_t>(bytes, pe.optional + 36);
    pe.image_size = read_value<std::uint32_t>(bytes, pe.optional + 56);
    pe.headers_size = read_value<std::uint32_t>(bytes, pe.optional + 60);
    pe.directory_count = read_value<std::uint32_t>(bytes, pe.optional + (pe.is_64() ? 108 : 92));
    pe.directories = pe.optional + (pe.is_64() ? 112 : 96);
    pe.directory_count = (std::min)(pe.directory_count,
                                    static_cast<std::uint32_t>(
                                        (pe.optional + pe.optional_size - pe.directories) / 8));
    pe.sections_offset = pe.optional + pe.optional_size;

    if (!pe.section_count || pe.section_count > 96 || !pe.image_size
        || pe.image_size > 0x40000000) {
        throw std::runtime_error("invalid PE geometry");
    }

    if (!power_of_two(pe.file_alignment) || !power_of_two(pe.section_alignment)
        || pe.file_alignment > 0x10000 || pe.section_alignment < pe.file_alignment) {
        throw std::runtime_error("invalid PE alignment geometry");
    }

    if (!pe.headers_size || pe.headers_size > pe.image_size || pe.entry >= pe.image_size) {
        throw std::runtime_error("invalid PE header geometry");
    }

    const auto table_size = static_cast<std::size_t>(pe.section_count) * 40;

    if (pe.sections_offset > bytes.size() || table_size > bytes.size() - pe.sections_offset) {
        throw std::runtime_error("truncated section table");
    }

    if (pe.sections_offset + table_size > pe.headers_size) {
        throw std::runtime_error("section table exceeds SizeOfHeaders");
    }

    pe.sections.reserve(pe.section_count);

    for (std::uint16_t index{}; index < pe.section_count; ++index) {
        const auto offset = pe.sections_offset + static_cast<std::size_t>(index) * 40;
        std::string name;
        for (std::size_t character{}; character < 8; ++character) {
            const auto value =
                static_cast<char>(std::to_integer<unsigned char>(bytes[offset + character]));
            if (!value) {
                break;
            }

            name.push_back(value);
        }

        Section section{offset,
                        std::move(name),
                        read_value<std::uint32_t>(bytes, offset + 8),
                        read_value<std::uint32_t>(bytes, offset + 12),
                        read_value<std::uint32_t>(bytes, offset + 16),
                        read_value<std::uint32_t>(bytes, offset + 20),
                        read_value<std::uint32_t>(bytes, offset + 36)};
        const auto span = (std::max)(section.virtual_size, section.raw_size);
        if (section.virtual_address >= pe.image_size
            || span > pe.image_size - section.virtual_address) {
            throw std::runtime_error("section exceeds SizeOfImage");
        }

        pe.sections.push_back(std::move(section));
    }

    auto ordered = pe.sections;
    std::ranges::sort(ordered, {}, &Section::virtual_address);

    for (std::size_t index = 1; index < ordered.size(); ++index) {
        const auto previous_end = static_cast<std::uint64_t>(ordered[index - 1].virtual_address)
            + (std::max)(ordered[index - 1].virtual_size, ordered[index - 1].raw_size);
        if (ordered[index].virtual_address < previous_end) {
            throw std::runtime_error("overlapping PE sections");
        }
    }

    return pe;
}

bool executable_rva(const Pe& pe, const std::uint32_t rva) {
    return std::ranges::any_of(pe.sections, [&](const auto& section) {
        return (section.characteristics & section_executable) && rva >= section.virtual_address
            && static_cast<std::uint64_t>(rva)
            < static_cast<std::uint64_t>(section.virtual_address) + section.virtual_size;
    });
}

const Section* section_at(const Pe& pe, const std::uint32_t rva, const std::size_t size = 1) {
    const auto found = std::ranges::find_if(pe.sections, [&](const auto& section) {
        const auto span = (std::max)(section.virtual_size, section.raw_size);
        return rva >= section.virtual_address && size <= span
            && rva - section.virtual_address <= span - size;
    });

    return found == pe.sections.end() ? nullptr : &*found;
}

std::string read_string(const std::span<const std::byte> bytes, const std::uint32_t offset) {
    if (offset >= bytes.size()) {
        throw std::runtime_error("string RVA is outside the PE image");
    }

    std::string value;

    for (std::size_t index = offset; index < bytes.size() && value.size() < 4096; ++index) {
        const auto character = static_cast<char>(std::to_integer<unsigned char>(bytes[index]));
        if (!character) {
            return value;
        }

        if (static_cast<unsigned char>(character) < 0x20
            || static_cast<unsigned char>(character) > 0x7e) {
            throw std::runtime_error("invalid PE string");
        }

        value.push_back(character);
    }

    throw std::runtime_error("unterminated PE string");
}

std::uint64_t
pointer_at(const std::span<const std::byte> image, const std::uint32_t rva, const bool is_64) {
    return is_64 ? read_value<std::uint64_t>(image, rva) : read_value<std::uint32_t>(image, rva);
}

struct Symbol {
    std::uint32_t ordinal{};
    std::string module;
    std::string name;
};

class SymbolIndex {
  public:
    SymbolIndex(kvmlib::MemProcFs& memory,
                const std::uint32_t process_id,
                const std::span<const kvmlib::ModuleInfo> modules,
                const std::uint64_t excluded_base) {
        for (const auto& module : modules) {
            if (!module.base || module.base == excluded_base) {
                continue;
            }

            const auto exports = memory.exports(process_id, module.name);

            if (!exports) {
                continue;
            }

            for (const auto& entry : *exports) {
                if (!entry.address) {
                    continue;
                }

                Symbol symbol{entry.ordinal, base_name(module.name), entry.name};
                const auto found = symbols_.find(entry.address);

                if (found == symbols_.end()
                    || (found->second.name.empty() && !symbol.name.empty())) {
                    symbols_.insert_or_assign(entry.address, std::move(symbol));
                }
            }
        }
    }

    const Symbol* resolve(const std::uint64_t address) const {
        const auto found = symbols_.find(address);

        return found == symbols_.end() ? nullptr : &found->second;
    }

  private:
    std::unordered_map<std::uint64_t, Symbol> symbols_;
};

std::vector<ImportGroup> imports_from_directory(const std::span<const std::byte> image,
                                                const Pe& pe,
                                                const SymbolIndex& symbols,
                                                std::unordered_set<std::uint32_t>& used) {
    std::vector<ImportGroup> groups;
    const auto [directory, size] = pe.directory(image, 1);
    if (!directory && !size) {
        return groups;
    }

    if (!directory || size < 20 || directory >= image.size() || size > image.size() - directory) {
        throw std::runtime_error("invalid import directory");
    }

    const auto pointer_size = pe.is_64() ? 8u : 4u;
    const auto ordinal_flag = pe.is_64() ? 0x8000000000000000ull : 0x80000000ull;
    bool terminated{};

    for (std::uint32_t descriptor = directory;
         descriptor + 20 <= static_cast<std::uint64_t>(directory) + size;
         descriptor += 20) {
        const auto original = read_value<std::uint32_t>(image, descriptor);
        const auto name_rva = read_value<std::uint32_t>(image, descriptor + 12);
        const auto first = read_value<std::uint32_t>(image, descriptor + 16);
        if (!original && !name_rva && !first) {
            terminated = true;
            break;
        }

        if (!first || first >= image.size()) {
            continue;
        }

        std::string descriptor_module;
        try {
            descriptor_module = base_name(read_string(image, name_rva));
        } catch (const std::runtime_error&) {
            descriptor_module.clear();
        }

        ImportGroup direct{descriptor_module, {}};
        bool lookup_valid = original && original < image.size() && !direct.module.empty();
        bool lookup_terminated{};

        if (lookup_valid) {
            for (std::uint32_t index{}; index < 65536; ++index) {
                const auto lookup_rva = static_cast<std::uint64_t>(original)
                    + static_cast<std::uint64_t>(index) * pointer_size;
                const auto slot_rva = static_cast<std::uint64_t>(first)
                    + static_cast<std::uint64_t>(index) * pointer_size;
                if (lookup_rva + pointer_size > image.size()
                    || slot_rva + pointer_size > image.size()) {
                    lookup_valid = false;
                    break;
                }

                const auto lookup =
                    pointer_at(image, static_cast<std::uint32_t>(lookup_rva), pe.is_64());

                if (!lookup) {
                    lookup_terminated = true;
                    break;
                }

                Import import{static_cast<std::uint32_t>(slot_rva), 0, {}};

                if (lookup & ordinal_flag) {
                    import.ordinal = static_cast<std::uint32_t>(lookup & 0xffff);
                } else if (lookup <= std::numeric_limits<std::uint32_t>::max()) {
                    try {
                        import.name = read_string(image, static_cast<std::uint32_t>(lookup) + 2);
                    } catch (...) {
                        lookup_valid = false;
                        break;
                    }
                } else {
                    lookup_valid = false;
                    break;
                }

                direct.imports.push_back(std::move(import));
            }
        }

        if (lookup_valid && lookup_terminated && !direct.imports.empty()) {
            for (const auto& import : direct.imports) {
                used.insert(import.slot);
            }
            groups.push_back(std::move(direct));
            continue;
        }

        ImportGroup resolved;

        for (std::uint32_t index{}; index < 65536; ++index) {
            const auto slot = static_cast<std::uint64_t>(first)
                + static_cast<std::uint64_t>(index) * pointer_size;
            if (slot + pointer_size > image.size()) {
                break;
            }

            const auto address = pointer_at(image, static_cast<std::uint32_t>(slot), pe.is_64());

            if (!address) {
                break;
            }

            const auto symbol = symbols.resolve(address);

            if (!symbol) {
                break;
            }

            if (!resolved.imports.empty() && lower(resolved.module) != lower(symbol->module)) {
                groups.push_back(std::move(resolved));
                resolved = {};
            }

            resolved.module = symbol->module;
            resolved.imports.push_back({static_cast<std::uint32_t>(slot),
                                        symbol->name.empty() ? symbol->ordinal : 0,
                                        symbol->name});
            used.insert(static_cast<std::uint32_t>(slot));
        }

        if (!resolved.imports.empty()) {
            groups.push_back(std::move(resolved));
        }
    }

    if (!terminated) {
        throw std::runtime_error("unterminated import directory");
    }

    return groups;
}

std::vector<ImportGroup> imports_from_map(std::vector<kvmlib::ImportInfo> entries,
                                          const Pe& pe,
                                          const SymbolIndex& symbols,
                                          std::unordered_set<std::uint32_t>& used) {
    const auto pointer_size = pe.is_64() ? 8u : 4u;
    std::ranges::sort(entries, {}, &kvmlib::ImportInfo::first_thunk_rva);
    std::vector<ImportGroup> result;

    for (const auto& entry : entries) {
        if (!entry.first_thunk_rva || entry.first_thunk_rva + pointer_size > pe.image_size
            || entry.module.empty() || used.contains(entry.first_thunk_rva)) {
            continue;
        }

        std::string name = entry.name;
        std::uint32_t ordinal{};

        if (name.empty()) {
            if (const auto symbol = symbols.resolve(entry.function_address)) {
                name = symbol->name;
                if (name.empty()) {
                    ordinal = symbol->ordinal;
                }
            }
        }

        if (name.empty() && !ordinal) {
            continue;
        }

        if (result.empty() || lower(result.back().module) != lower(entry.module)
            || result.back().imports.back().slot + pointer_size != entry.first_thunk_rva) {
            result.push_back({base_name(entry.module), {}});
        }

        result.back().imports.push_back({entry.first_thunk_rva, ordinal, std::move(name)});
        used.insert(entry.first_thunk_rva);
    }

    return result;
}

std::set<std::uint32_t> referenced_slots(const std::span<const std::byte> image,
                                         const Pe& pe,
                                         const std::uint64_t runtime_base) {
    std::set<std::uint32_t> result;
    const auto pointer_size = pe.is_64() ? 8u : 4u;
    std::size_t total{};

    for (const auto& section : pe.sections) {
        if ((section.characteristics & section_executable)
            && section.virtual_address < image.size()) {
            total += (std::min)(static_cast<std::size_t>(section.virtual_size),
                                image.size() - section.virtual_address);
        }
    }

    std::size_t processed{};
    csh handle{};

    if (cs_open(CS_ARCH_X86, pe.is_64() ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK) {
        throw std::runtime_error("unable to initialize x86 decoder");
    }

    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
        cs_close(&handle);
        throw std::runtime_error("unable to enable x86 decoder details");
    }

    cs_insn* instruction = cs_malloc(handle);

    if (!instruction) {
        cs_close(&handle);
        throw std::runtime_error("unable to allocate x86 decoder instruction");
    }

    for (const auto& section : pe.sections) {
        if (!(section.characteristics & section_executable) || !section.virtual_size
            || section.virtual_address >= image.size()) {
            continue;
        }

        const auto size = (std::min)(static_cast<std::size_t>(section.virtual_size),
                                     image.size() - section.virtual_address);
        const auto code = image.subspan(section.virtual_address, size);
        auto cursor = reinterpret_cast<const std::uint8_t*>(code.data());
        auto remaining = code.size();
        auto address = runtime_base + section.virtual_address;
        std::size_t next_progress = 1 << 20;

        while (remaining) {
            if (!cs_disasm_iter(handle, &cursor, &remaining, &address, instruction)) {
                ++cursor;
                --remaining;
                ++address;
                continue;
            }

            const auto& detail = instruction->detail->x86;

            for (std::uint8_t operand_index{}; operand_index < detail.op_count; ++operand_index) {
                const auto& operand = detail.operands[operand_index];
                if (operand.type != X86_OP_MEM || operand.mem.index != X86_REG_INVALID) {
                    continue;
                }

                std::uint64_t target_address{};

                if (operand.mem.base == X86_REG_RIP) {
                    target_address = instruction->address + instruction->size + operand.mem.disp;
                } else if (operand.mem.base == X86_REG_INVALID) {
                    target_address = static_cast<std::uint64_t>(operand.mem.disp);
                } else {
                    continue;
                }

                if (target_address < runtime_base
                    || target_address - runtime_base > std::numeric_limits<std::uint32_t>::max()) {
                    continue;
                }

                const auto rva = static_cast<std::uint32_t>(target_address - runtime_base);
                const auto target = section_at(pe, rva, pointer_size);

                if (target && !(target->characteristics & section_executable)) {
                    result.insert(rva);
                }
            }

            const auto section_processed = code.size() - remaining;

            if (section_processed >= next_progress) {
                const auto percent = total
                    ? static_cast<unsigned>(((processed + section_processed) * 100) / total)
                    : 100u;
                std::cout << "\rRecovering imports: " << percent << "%" << std::flush;
                next_progress = section_processed + (1 << 20);
            }
        }

        processed += code.size();
    }

    std::cout << "\rRecovering imports: 100%\n";
    cs_free(instruction, 1);
    cs_close(&handle);

    return result;
}

std::vector<ImportGroup> imports_from_references(const std::span<const std::byte> image,
                                                 const Pe& pe,
                                                 const std::uint64_t runtime_base,
                                                 const SymbolIndex& symbols,
                                                 std::unordered_set<std::uint32_t>& used) {
    const auto pointer_size = pe.is_64() ? 8u : 4u;
    std::vector<std::pair<std::uint32_t, const Symbol*>> found;

    for (const auto slot : referenced_slots(image, pe, runtime_base)) {
        if (used.contains(slot)) {
            continue;
        }

        if (const auto symbol = symbols.resolve(pointer_at(image, slot, pe.is_64()))) {
            found.push_back({slot, symbol});
        }
    }

    std::ranges::sort(found, {}, &std::pair<std::uint32_t, const Symbol*>::first);
    std::vector<ImportGroup> result;

    for (std::size_t index{}; index < found.size();) {
        ImportGroup group{found[index].second->module, {}};
        auto expected = found[index].first;

        while (index < found.size() && found[index].first == expected
               && lower(found[index].second->module) == lower(group.module)) {
            const auto& symbol = *found[index].second;
            group.imports.push_back(
                {found[index].first, symbol.name.empty() ? symbol.ordinal : 0, symbol.name});
            used.insert(found[index].first);
            expected += pointer_size;
            ++index;
        }

        result.push_back(std::move(group));
    }

    return result;
}

bool usable_relocations(const std::span<const std::byte> image, const Pe& pe) {
    const auto [directory, size] = pe.directory(image, 5);

    if (!directory || size < 8 || directory >= image.size() || size > image.size() - directory) {
        return false;
    }

    std::uint32_t offset{};
    std::size_t applied{};

    while (offset < size) {
        if (size - offset < 8) {
            return false;
        }

        const auto block = directory + offset;
        const auto page = read_value<std::uint32_t>(image, block);
        const auto block_size = read_value<std::uint32_t>(image, block + 4);

        if (block_size < 8 || block_size > size - offset || block_size % 2) {
            return false;
        }

        for (std::uint32_t entry = 8; entry < block_size; entry += 2) {
            const auto value = read_value<std::uint16_t>(image, block + entry);
            const auto type = value >> 12;
            if (!type) {
                continue;
            }

            const auto target = static_cast<std::uint64_t>(page) + (value & 0x0fff);

            if (pe.is_64()) {
                if (type != 10 || target + 8 > image.size()) {
                    return false;
                }
            } else {
                if (type != 3 || target + 4 > image.size()) {
                    return false;
                }
            }

            ++applied;
        }

        offset += block_size;
    }

    return applied != 0;
}

void set_directory(const std::span<std::byte> image,
                   const Pe& pe,
                   const std::size_t index,
                   const std::uint32_t rva,
                   const std::uint32_t size) {
    if (index >= pe.directory_count
        || pe.directories + index * 8 + 8 > pe.optional + pe.optional_size) {
        return;
    }

    write_value<std::uint32_t>(image, pe.directories + index * 8, rva);
    write_value<std::uint32_t>(image, pe.directories + index * 8 + 4, size);
}

void fix_entry(std::vector<std::byte>& image,
               const Pe& pe,
               const std::uint64_t runtime_base,
               const std::uint64_t module_entry) {
    if (executable_rva(pe, pe.entry)) {
        return;
    }

    if (module_entry < runtime_base
        || module_entry - runtime_base > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("unable to recover the original executable entry point");
    }

    const auto entry = static_cast<std::uint32_t>(module_entry - runtime_base);

    if (!executable_rva(pe, entry)) {
        throw std::runtime_error("module metadata does not contain an executable entry point");
    }

    write_value<std::uint32_t>(image, pe.optional + 16, entry);
}

std::size_t append_string(std::vector<std::byte>& bytes, const std::string_view value) {
    const auto offset = bytes.size();
    for (const auto character : value) {
        bytes.push_back(static_cast<std::byte>(character));
    }

    bytes.push_back(std::byte{});

    return offset;
}

void pad(std::vector<std::byte>& bytes, const std::size_t alignment) {
    while (bytes.size() % alignment) {
        bytes.push_back(std::byte{});
    }
}

std::uint32_t append_section(std::vector<std::byte>& image,
                             const Pe& pe,
                             const std::string_view name,
                             const std::span<const std::byte> data,
                             const std::uint32_t characteristics) {
    const auto new_header = pe.sections_offset + static_cast<std::size_t>(pe.section_count) * 40;
    const auto first_section =
        std::ranges::min(pe.sections, {}, &Section::virtual_address).virtual_address;
    if (pe.section_count == 96 || new_header + 40 > first_section) {
        throw std::runtime_error("the PE headers have no room for an analysis section");
    }

    const auto virtual_address = align_up(pe.image_size, pe.section_alignment);

    if (data.size() > std::numeric_limits<std::uint32_t>::max() - virtual_address) {
        throw std::runtime_error("analysis section exceeds PE address space");
    }

    const auto image_size =
        align_up(virtual_address + static_cast<std::uint32_t>(data.size()), pe.section_alignment);

    image.resize(image_size);
    std::ranges::copy(data, image.begin() + virtual_address);

    std::fill_n(image.begin() + static_cast<std::vector<std::byte>::difference_type>(new_header),
                40,
                std::byte{});

    for (std::size_t index{}; index < (std::min)(name.size(), std::size_t{8}); ++index) {
        image[new_header + index] = static_cast<std::byte>(name[index]);
    }

    write_value<std::uint32_t>(image, new_header + 8, static_cast<std::uint32_t>(data.size()));
    write_value<std::uint32_t>(image, new_header + 12, virtual_address);
    write_value<std::uint32_t>(image, new_header + 36, characteristics);
    write_value<std::uint16_t>(image, pe.nt + 6, pe.section_count + 1);
    write_value<std::uint32_t>(image, pe.optional + 56, image_size);

    return virtual_address;
}

struct ExceptionStats {
    std::size_t kept{}, dropped{};
};

ExceptionStats normalize_exceptions(std::vector<std::byte>& image, const Pe& pe) {
    const auto [directory, size] = pe.directory(image, 3);

    if (!directory && !size) {
        return {};
    }

    if (!directory || directory >= image.size() || size > image.size() - directory) {
        set_directory(image, pe, 3, 0, 0);
        return {0, size / 12};
    }

    struct Entry {
        std::uint32_t begin, end, unwind;
    };

    std::vector<Entry> entries;
    const auto count = size / 12;
    entries.reserve(count);
    bool ordered = true;
    std::uint32_t previous_begin{};

    for (std::size_t index{}; index < count; ++index) {
        const auto offset = directory + index * 12;
        const Entry entry{read_value<std::uint32_t>(image, offset),
                          read_value<std::uint32_t>(image, offset + 4),
                          read_value<std::uint32_t>(image, offset + 8)};
        if (!entry.begin || entry.begin >= entry.end || !executable_rva(pe, entry.begin)
            || !executable_rva(pe, entry.end - 1) || !entry.unwind
            || !section_at(pe, entry.unwind, 4)) {
            continue;
        }

        if (!entries.empty() && entry.begin < previous_begin) {
            ordered = false;
        }

        previous_begin = entry.begin;
        entries.push_back(entry);
    }

    std::ranges::sort(entries, [](const Entry& left, const Entry& right) {
        if (left.begin != right.begin) {
            return left.begin < right.begin;
        }
        if (left.end != right.end) {
            return left.end < right.end;
        }
        return left.unwind < right.unwind;
    });

    const auto unique = std::ranges::unique(entries, [](const Entry& left, const Entry& right) {
        return left.begin == right.begin && left.end == right.end && left.unwind == right.unwind;
    });
    entries.erase(unique.begin(), unique.end());

    const auto dropped = count - entries.size() + (size % 12 ? 1 : 0);

    if (!dropped && ordered) {
        return {entries.size(), 0};
    }

    if (entries.empty()) {
        set_directory(image, pe, 3, 0, 0);
        return {0, dropped};
    }

    std::vector<std::byte> table(entries.size() * 12);

    for (std::size_t index{}; index < entries.size(); ++index) {
        write_value<std::uint32_t>(table, index * 12, entries[index].begin);
        write_value<std::uint32_t>(table, index * 12 + 4, entries[index].end);
        write_value<std::uint32_t>(table, index * 12 + 8, entries[index].unwind);
    }

    const auto rva =
        append_section(image, pe, ".pdata2", table, section_initialized | section_readable);
    set_directory(image, pe, 3, rva, static_cast<std::uint32_t>(table.size()));

    return {entries.size(), dropped};
}

void append_import_section(std::vector<std::byte>& image, Pe pe, std::vector<ImportGroup> groups) {
    if (groups.empty()) {
        const auto [directory, size] = pe.directory(image, 1);
        if (directory || size) {
            throw std::runtime_error(
                "the image has imports but none could be reconstructed safely");
        }
        set_directory(image, pe, 12, 0, 0);
        return;
    }

    for (const auto& group : groups) {
        if (group.module.empty() || group.imports.empty()) {
            throw std::runtime_error("invalid reconstructed import group");
        }
    }

    std::ranges::sort(groups, [](const auto& left, const auto& right) {
        return left.imports.front().slot < right.imports.front().slot;
    });

    const auto pointer_size = pe.is_64() ? 8u : 4u;
    std::unordered_set<std::uint32_t> slots;

    for (const auto& group : groups) {
        auto expected = group.imports.front().slot;

        for (const auto& import : group.imports) {
            if (import.slot != expected || import.slot + pointer_size > image.size()
                || !slots.insert(import.slot).second || (import.name.empty() && !import.ordinal)) {
                throw std::runtime_error("invalid reconstructed import slots");
            }

            expected += pointer_size;
        }
    }

    const auto new_header = pe.sections_offset + static_cast<std::size_t>(pe.section_count) * 40;
    const auto first_section =
        std::ranges::min(pe.sections, {}, &Section::virtual_address).virtual_address;
    if (pe.section_count == 96 || new_header + 40 > first_section) {
        throw std::runtime_error("the PE headers have no room for a reconstructed import section");
    }

    const auto virtual_address = align_up(pe.image_size, pe.section_alignment);
    std::vector<std::byte> data((groups.size() + 1) * 20);
    const auto ordinal_flag = pe.is_64() ? 0x8000000000000000ull : 0x80000000ull;
    std::uint32_t iat_begin = std::numeric_limits<std::uint32_t>::max();
    std::uint32_t iat_end{};

    for (std::size_t group_index{}; group_index < groups.size(); ++group_index) {
        const auto& group = groups[group_index];
        const auto name_offset = append_string(data, base_name(group.module));
        std::vector<std::uint64_t> lookups;
        lookups.reserve(group.imports.size());

        for (const auto& import : group.imports) {
            if (import.ordinal) {
                lookups.push_back(ordinal_flag | import.ordinal);
            } else {
                pad(data, 2);
                const auto name = data.size();
                data.resize(data.size() + 2);
                append_string(data, import.name);
                lookups.push_back(static_cast<std::uint64_t>(virtual_address) + name);
            }
        }

        pad(data, pointer_size);
        const auto table = data.size();

        for (const auto lookup : lookups) {
            const auto begin = data.size();
            data.resize(begin + pointer_size);
            if (pe.is_64()) {
                write_value<std::uint64_t>(data, begin, lookup);
            } else {
                write_value<std::uint32_t>(data, begin, static_cast<std::uint32_t>(lookup));
            }
        }

        data.resize(data.size() + pointer_size);
        const auto descriptor = group_index * 20;
        write_value<std::uint32_t>(
            data, descriptor, virtual_address + static_cast<std::uint32_t>(table));
        write_value<std::uint32_t>(
            data, descriptor + 12, virtual_address + static_cast<std::uint32_t>(name_offset));
        write_value<std::uint32_t>(data, descriptor + 16, group.imports.front().slot);

        for (std::size_t index{}; index < group.imports.size(); ++index) {
            const auto slot = group.imports[index].slot;
            if (pe.is_64()) {
                write_value<std::uint64_t>(image, slot, lookups[index]);
            } else {
                write_value<std::uint32_t>(image, slot, static_cast<std::uint32_t>(lookups[index]));
            }
        }

        iat_begin = (std::min)(iat_begin, group.imports.front().slot);
        iat_end = (std::max)(iat_end,
                             static_cast<std::uint32_t>(group.imports.back().slot + pointer_size));
    }

    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("reconstructed import section is too large");
    }

    const auto virtual_size = static_cast<std::uint32_t>(data.size());

    if (virtual_size > std::numeric_limits<std::uint32_t>::max() - virtual_address) {
        throw std::runtime_error("reconstructed import section overflows the image");
    }

    const auto new_image_size = align_up(virtual_address + virtual_size, pe.section_alignment);
    image.resize(new_image_size);
    std::ranges::copy(data, image.begin() + virtual_address);

    std::fill_n(image.begin() + static_cast<std::vector<std::byte>::difference_type>(new_header),
                40,
                std::byte{});

    const std::string name = ".idata2";

    for (std::size_t index{}; index < name.size(); ++index) {
        image[new_header + index] = static_cast<std::byte>(name[index]);
    }

    write_value<std::uint32_t>(image, new_header + 8, virtual_size);
    write_value<std::uint32_t>(image, new_header + 12, virtual_address);
    write_value<std::uint32_t>(
        image, new_header + 36, section_initialized | section_readable | section_writable);
    write_value<std::uint16_t>(image, pe.nt + 6, pe.section_count + 1);
    write_value<std::uint32_t>(image, pe.optional + 56, new_image_size);
    set_directory(
        image, pe, 1, virtual_address, static_cast<std::uint32_t>((groups.size() + 1) * 20));
    set_directory(image, pe, 11, 0, 0);

    if (section_at(pe, iat_begin, iat_end - iat_begin)) {
        set_directory(image, pe, 12, iat_begin, iat_end - iat_begin);
    } else {
        set_directory(image, pe, 12, 0, 0);
    }
}

void normalize_directories(std::vector<std::byte>& image, const Pe& pe) {
    set_directory(image, pe, 4, 0, 0);

    for (std::size_t index{}; index < pe.directory_count; ++index) {
        if (index == 4) {
            continue;
        }

        const auto [rva, size] = pe.directory(image, index);

        if (!rva && !size) {
            continue;
        }

        if (!rva || !size || rva >= image.size() || size > image.size() - rva) {
            set_directory(image, pe, index, 0, 0);
        }
    }

    const auto [tls_rva, tls_size] = pe.directory(image, 9);
    const auto expected = pe.is_64() ? 40u : 24u;

    if (tls_rva && tls_rva <= image.size() && expected <= image.size() - tls_rva) {
        set_directory(image, pe, 9, tls_rva, expected);
    } else if (tls_rva || tls_size) {
        set_directory(image, pe, 9, 0, 0);
    }
}

std::uint32_t rva_to_raw(const Pe& pe, const std::uint32_t rva, const std::size_t size = 1) {
    if (rva < pe.headers_size && size <= pe.headers_size - rva) {
        return rva;
    }

    for (const auto& section : pe.sections) {
        if (!section.raw_size || rva < section.virtual_address) {
            continue;
        }

        const auto relative = rva - section.virtual_address;

        if (size <= section.raw_size && relative <= section.raw_size - size) {
            return section.raw_address + relative;
        }
    }

    throw std::runtime_error("RVA does not map to file data");
}

std::uint32_t checksum(const std::span<const std::byte> file, const std::size_t checksum_offset) {
    std::uint64_t sum{};

    for (std::size_t offset{}; offset < file.size(); offset += 2) {
        if (offset == checksum_offset || offset == checksum_offset + 2) {
            continue;
        }

        std::uint16_t word = std::to_integer<unsigned char>(file[offset]);

        if (offset + 1 < file.size()) {
            word |= static_cast<std::uint16_t>(std::to_integer<unsigned char>(file[offset + 1]))
                << 8;
        }

        sum = (sum & 0xffff) + (sum >> 16) + word;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return static_cast<std::uint32_t>(sum + file.size());
}

std::vector<std::byte> rebuild_file(std::vector<std::byte>& image) {
    auto pe = parse_pe(image);
    const auto table_end = pe.sections_offset + static_cast<std::size_t>(pe.section_count) * 40;

    if (table_end > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("section table is too large");
    }

    const auto headers = align_up(
        (std::max)(pe.headers_size, static_cast<std::uint32_t>(table_end)), pe.file_alignment);
    const auto first_section =
        std::ranges::min(pe.sections, {}, &Section::virtual_address).virtual_address;
    if (headers > first_section) {
        throw std::runtime_error("rebuilt headers overlap the first section");
    }

    std::uint64_t cursor = headers;
    std::uint64_t code_size{};
    std::uint64_t initialized_size{};
    std::uint64_t uninitialized_size{};

    for (auto& section : pe.sections) {
        const auto available =
            section.virtual_address < image.size() ? image.size() - section.virtual_address : 0;
        const auto uninitialized = (section.characteristics & section_uninitialized)
            && !(section.characteristics & (section_code | section_initialized));
        const auto requested = section.virtual_size ? section.virtual_size : section.raw_size;
        const auto content =
            uninitialized ? 0 : (std::min)(static_cast<std::size_t>(requested), available);
        section.raw_address = content ? static_cast<std::uint32_t>(cursor) : 0;
        section.raw_size =
            content ? align_up(static_cast<std::uint32_t>(content), pe.file_alignment) : 0;
        cursor += section.raw_size;

        if (cursor > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("rebuilt PE exceeds the file size limit");
        }

        if (section.characteristics & section_code) {
            code_size += section.raw_size;
        }

        if (section.characteristics & section_initialized) {
            initialized_size += section.raw_size;
        }

        if (section.characteristics & section_uninitialized) {
            uninitialized_size += section.virtual_size;
        }
    }

    if (code_size > std::numeric_limits<std::uint32_t>::max()
        || initialized_size > std::numeric_limits<std::uint32_t>::max()
        || uninitialized_size > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("rebuilt PE size fields overflow");
    }

    std::vector<std::byte> output(static_cast<std::size_t>(cursor));
    std::copy_n(
        image.begin(), (std::min)(image.size(), static_cast<std::size_t>(headers)), output.begin());
    write_value<std::uint32_t>(output, pe.optional + 4, static_cast<std::uint32_t>(code_size));
    write_value<std::uint32_t>(
        output, pe.optional + 8, static_cast<std::uint32_t>(initialized_size));
    write_value<std::uint32_t>(
        output, pe.optional + 12, static_cast<std::uint32_t>(uninitialized_size));
    write_value<std::uint32_t>(output, pe.optional + 60, headers);
    write_value<std::uint32_t>(output, pe.optional + 64, 0);

    for (const auto& section : pe.sections) {
        write_value<std::uint32_t>(output, section.header + 16, section.raw_size);
        write_value<std::uint32_t>(output, section.header + 20, section.raw_address);
        if (!section.raw_size) {
            continue;
        }

        const auto content =
            (std::min)(static_cast<std::size_t>(section.virtual_size ? section.virtual_size
                                                                     : section.raw_size),
                       image.size() - section.virtual_address);
        std::copy_n(
            image.begin() + section.virtual_address, content, output.begin() + section.raw_address);
    }

    pe = parse_pe(output);
    const auto [debug_rva, debug_size] = pe.directory(output, 6);

    if (debug_rva && debug_size >= 28) {
        const auto debug_raw = rva_to_raw(pe, debug_rva, 28);

        for (std::uint32_t offset{}; offset + 28 <= debug_size; offset += 28) {
            if (debug_raw + offset + 28 > output.size()) {
                throw std::runtime_error("invalid debug directory");
            }

            const auto data_rva = read_value<std::uint32_t>(output, debug_raw + offset + 20);
            const auto data_size = read_value<std::uint32_t>(output, debug_raw + offset + 16);
            const auto data_raw = data_rva && data_size ? rva_to_raw(pe, data_rva, data_size) : 0;
            write_value<std::uint32_t>(output, debug_raw + offset + 24, data_raw);
        }
    }

    write_value<std::uint32_t>(output, pe.optional + 64, checksum(output, pe.optional + 64));

    return output;
}

void validate_imports(const std::span<const std::byte> file, const Pe& pe) {
    const auto [directory, size] = pe.directory(file, 1);

    if (!directory && !size) {
        return;
    }

    if (!directory || size < 20 || size % 20) {
        throw std::runtime_error("invalid rebuilt import directory size");
    }

    const auto pointer_size = pe.is_64() ? 8u : 4u;
    const auto ordinal_flag = pe.is_64() ? 0x8000000000000000ull : 0x80000000ull;
    bool terminated{};

    for (std::uint32_t offset{}; offset + 20 <= size; offset += 20) {
        const auto descriptor = rva_to_raw(pe, directory + offset, 20);
        const auto original = read_value<std::uint32_t>(file, descriptor);
        const auto name = read_value<std::uint32_t>(file, descriptor + 12);
        const auto first = read_value<std::uint32_t>(file, descriptor + 16);
        if (!original && !name && !first) {
            terminated = true;
            break;
        }

        if (!original || !name || !first) {
            throw std::runtime_error("incomplete rebuilt import descriptor");
        }

        static_cast<void>(read_string(file, rva_to_raw(pe, name)));
        bool thunk_terminated{};

        for (std::uint32_t index{}; index < 65536; ++index) {
            const auto lookup_rva = static_cast<std::uint64_t>(original)
                + static_cast<std::uint64_t>(index) * pointer_size;
            const auto slot_rva = static_cast<std::uint64_t>(first)
                + static_cast<std::uint64_t>(index) * pointer_size;
            if (lookup_rva > std::numeric_limits<std::uint32_t>::max()
                || slot_rva > std::numeric_limits<std::uint32_t>::max()) {
                throw std::runtime_error("rebuilt import thunk overflow");
            }

            const auto lookup =
                pointer_at(file,
                           rva_to_raw(pe, static_cast<std::uint32_t>(lookup_rva), pointer_size),
                           pe.is_64());
            static_cast<void>(rva_to_raw(pe, static_cast<std::uint32_t>(slot_rva), pointer_size));

            if (!lookup) {
                thunk_terminated = true;
                break;
            }

            if (!(lookup & ordinal_flag)) {
                if (lookup > std::numeric_limits<std::uint32_t>::max()) {
                    throw std::runtime_error("rebuilt import name RVA overflow");
                }
                static_cast<void>(
                    read_string(file, rva_to_raw(pe, static_cast<std::uint32_t>(lookup) + 2)));
            }
        }

        if (!thunk_terminated) {
            throw std::runtime_error("unterminated rebuilt import thunk");
        }
    }

    if (!terminated) {
        throw std::runtime_error("unterminated rebuilt import descriptors");
    }
}

void validate_exceptions(const std::span<const std::byte> file, const Pe& pe) {
    if (!pe.is_64()) {
        return;
    }

    const auto [directory, size] = pe.directory(file, 3);

    if (!directory && !size) {
        return;
    }

    if (!directory || !size || size % 12) {
        throw std::runtime_error("invalid rebuilt exception directory size");
    }

    std::uint32_t previous{};

    for (std::uint32_t offset{}; offset < size; offset += 12) {
        const auto raw = rva_to_raw(pe, directory + offset, 12);
        const auto begin = read_value<std::uint32_t>(file, raw);
        const auto end = read_value<std::uint32_t>(file, raw + 4);
        const auto unwind = read_value<std::uint32_t>(file, raw + 8);
        if (!begin || begin >= end || (offset && begin < previous) || !executable_rva(pe, begin)
            || !executable_rva(pe, end - 1) || !unwind) {
            throw std::runtime_error("invalid rebuilt runtime-function entry");
        }

        static_cast<void>(rva_to_raw(pe, unwind, 4));
        previous = begin;
    }
}

} // namespace

ImageInfo inspect_pe_image(const std::span<const std::byte> image) {
    const auto pe = parse_pe(image);
    ImageInfo result{pe.image_size, pe.headers_size, pe.entry, pe.image_base, pe.is_64(), {}, {}};
    result.sections.reserve(pe.sections.size());

    for (const auto& section : pe.sections) {
        result.sections.push_back({section.name,
                                   section.virtual_address,
                                   section.virtual_size,
                                   section.raw_size,
                                   section.characteristics});
    }

    result.directories.reserve(pe.directory_count);

    for (std::size_t index{}; index < pe.directory_count; ++index) {
        const auto [virtual_address, size] = pe.directory(image, index);
        result.directories.push_back({virtual_address, size});
    }

    return result;
}

std::vector<ImportGroup> recover_imports(const std::span<const std::byte> image,
                                         const std::uint64_t runtime_base,
                                         kvmlib::MemProcFs& memory,
                                         const std::uint32_t process_id,
                                         const std::span<const kvmlib::ModuleInfo> modules,
                                         const std::uint64_t excluded_base,
                                         std::size_t& recovered_count) {
    const auto pe = parse_pe(image);
    const SymbolIndex symbols(memory, process_id, modules, excluded_base);
    std::unordered_set<std::uint32_t> used;
    std::vector<ImportGroup> groups;

    const auto main_module = std::ranges::find(modules, excluded_base, &kvmlib::ModuleInfo::base);

    if (main_module != modules.end()) {
        if (auto mapped = memory.imports(process_id, main_module->name);
            mapped && !mapped->empty()) {
            groups = imports_from_map(std::move(*mapped), pe, symbols, used);
        }
    }

    if (groups.empty()) {
        groups = imports_from_directory(image, pe, symbols, used);
    }

    auto recovered = imports_from_references(image, pe, runtime_base, symbols, used);
    recovered_count =
        std::ranges::fold_left(recovered, std::size_t{}, [](const auto count, const auto& group) {
            return count + group.imports.size();
        });
    groups.insert(groups.end(),
                  std::make_move_iterator(recovered.begin()),
                  std::make_move_iterator(recovered.end()));

    return groups;
}

Reconstruction reconstruct_pe(std::vector<std::byte> image,
                              const std::uint64_t runtime_base,
                              const std::uint64_t module_entry,
                              const std::vector<ImportGroup>& imports,
                              const std::size_t recovered_imports) {
    auto pe = parse_pe(image);
    std::string relocation_status;

    if (runtime_base != pe.image_base || !usable_relocations(image, pe)) {
        if (pe.is_64()) {
            write_value<std::uint64_t>(image, pe.optional + 24, runtime_base);
        } else if (runtime_base <= std::numeric_limits<std::uint32_t>::max()) {
            write_value<std::uint32_t>(
                image, pe.optional + 28, static_cast<std::uint32_t>(runtime_base));
        } else {
            throw std::runtime_error("32-bit image runtime base is out of range");
        }

        const auto flags = read_value<std::uint16_t>(image, pe.optional + 70);
        write_value<std::uint16_t>(
            image,
            pe.optional + 70,
            flags & static_cast<std::uint16_t>(~(dynamic_base | high_entropy_va)));
        const auto characteristics = read_value<std::uint16_t>(image, pe.nt + 22);
        write_value<std::uint16_t>(image, pe.nt + 22, characteristics | relocs_stripped);
        set_directory(image, pe, 5, 0, 0);

        relocation_status = "stripped; image pinned to runtime base";
    } else {
        const auto characteristics = read_value<std::uint16_t>(image, pe.nt + 22);
        write_value<std::uint16_t>(
            image, pe.nt + 22, characteristics & static_cast<std::uint16_t>(~relocs_stripped));
        relocation_status = "preserved at preferred base";
    }

    fix_entry(image, pe, runtime_base, module_entry);
    pe = parse_pe(image);

    const auto exceptions = normalize_exceptions(image, pe);
    pe = parse_pe(image);

    append_import_section(image, pe, imports);
    pe = parse_pe(image);

    normalize_directories(image, pe);

    auto file = rebuild_file(image);
    validate_pe_file(file);

    const auto import_count =
        std::ranges::fold_left(imports, std::size_t{}, [](const auto count, const auto& group) {
            return count + group.imports.size();
        });

    return {std::move(file),
            import_count,
            imports.size(),
            recovered_imports,
            std::move(relocation_status),
            exceptions.kept,
            exceptions.dropped};
}

void validate_pe_file(const std::span<const std::byte> file) {
    const auto pe = parse_pe(file);

    if (pe.headers_size > file.size()) {
        throw std::runtime_error("rebuilt headers exceed the output file");
    }

    if (!executable_rva(pe, pe.entry)) {
        throw std::runtime_error("rebuilt entry point is not executable");
    }

    std::vector<std::pair<std::uint32_t, std::uint32_t>> ranges;

    for (const auto& section : pe.sections) {
        if (!section.raw_size) {
            continue;
        }

        if (section.raw_address % pe.file_alignment || section.raw_size % pe.file_alignment
            || section.raw_address > file.size()
            || section.raw_size > file.size() - section.raw_address) {
            throw std::runtime_error("invalid rebuilt section file range");
        }

        ranges.push_back({section.raw_address, section.raw_address + section.raw_size});
    }

    std::ranges::sort(ranges);

    for (std::size_t index = 1; index < ranges.size(); ++index) {
        if (ranges[index].first < ranges[index - 1].second) {
            throw std::runtime_error("overlapping rebuilt section file ranges");
        }
    }

    for (std::size_t index{}; index < pe.directory_count; ++index) {
        const auto [rva, size] = pe.directory(file, index);
        if (!rva && !size) {
            continue;
        }

        if (!rva || !size) {
            throw std::runtime_error("incomplete rebuilt data directory");
        }

        if (index == 4) {
            if (rva > file.size() || size > file.size() - rva) {
                throw std::runtime_error("invalid rebuilt security directory");
            }
        } else {
            static_cast<void>(rva_to_raw(pe, rva, size));
        }
    }

    const auto [tls_rva, tls_size] = pe.directory(file, 9);

    if (tls_rva && tls_size != (pe.is_64() ? 40u : 24u)) {
        throw std::runtime_error("invalid rebuilt TLS directory size");
    }

    validate_imports(file, pe);
    validate_exceptions(file, pe);

    const auto stored = read_value<std::uint32_t>(file, pe.optional + 64);

    if (!stored || stored != checksum(file, pe.optional + 64)) {
        throw std::runtime_error("invalid rebuilt PE checksum");
    }
}

} // namespace runtime_dumper
