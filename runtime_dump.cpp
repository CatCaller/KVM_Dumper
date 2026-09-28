#include "runtime_dump.h"

#include "backing_image.h"
#include "pe_reconstruct.h"
#include "qmp_freeze.h"

#include <kvmlib/kvmlib.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <ranges>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace runtime_dumper {
namespace {

constexpr std::size_t page_size = 0x1000;
constexpr std::uint64_t cr3_mask = 0x000ffffffffff000;
constexpr std::uint32_t section_code = 0x00000020;
constexpr std::uint32_t section_initialized = 0x00000040;
constexpr std::uint32_t section_executable = 0x20000000;

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

std::string process_key(const std::string_view value) {
    auto name = lower(base_name(value));

    if (name.ends_with(".exe")) {
        name.resize(name.size() - 4);
    }

    return name;
}

std::vector<std::string> command_line(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }

    const std::string data(std::istreambuf_iterator<char>(file), {});
    std::vector<std::string> result;

    for (std::size_t begin{}; begin < data.size();) {
        const auto end = data.find('\0', begin);
        result.push_back(
            data.substr(begin, end == std::string::npos ? data.size() - begin : end - begin));

        if (end == std::string::npos) {
            break;
        }

        begin = end + 1;
    }

    return result;
}

std::vector<std::string> qemu_devices() {
    if (const auto value = std::getenv("VMM_DEVICE"); value && *value) {
        return {value};
    }

    std::vector<std::string> result;
    std::error_code error;

    for (const auto& entry : std::filesystem::directory_iterator("/proc", error)) {
        if (error) {
            break;
        }

        const auto name = entry.path().filename().string();
        if (name.empty() || !std::ranges::all_of(name, [](const unsigned char value) {
                return std::isdigit(value);
            })) {
            continue;
        }

        std::ifstream comm(entry.path() / "comm");
        std::string executable;
        std::getline(comm, executable);

        if (!executable.starts_with("qemu-system")) {
            continue;
        }

        const auto arguments = command_line(entry.path() / "cmdline");
        std::string qmp;

        for (std::size_t index{}; index + 1 < arguments.size(); ++index) {
            if (arguments[index] != "-qmp") {
                continue;
            }

            qmp = arguments[index + 1];

            if (qmp.starts_with("unix:")) {
                qmp.erase(0, 5);
            }

            if (const auto comma = qmp.find(','); comma != std::string::npos) {
                qmp.resize(comma);
            }

            break;
        }

        auto device = "qemu://hugepage-pid=" + name;

        if (!qmp.empty()) {
            device += ",qmp=" + qmp;
        }

        result.push_back(std::move(device));
    }

    if (result.empty()) {
        throw std::runtime_error(
            "no running QEMU guest was found; set VMM_DEVICE explicitly if needed");
    }

    return result;
}

std::uint32_t find_process(kvmlib::MemProcFs& memory, const std::string_view process_name) {
    if (!memory.refresh()) {
        throw std::runtime_error("unable to refresh the guest process list");
    }

    const auto processes = memory.processes();
    if (!processes) {
        throw std::runtime_error("unable to enumerate guest processes");
    }

    const auto exact_name = lower(base_name(process_name));
    const auto expected = process_key(process_name);
    std::set<std::uint32_t> exact_matches;
    std::set<std::uint32_t> normalized_matches;
    std::vector<std::string> related;

    for (const auto& process : *processes) {
        if (lower(base_name(process.name)) == exact_name) {
            exact_matches.insert(process.process_id);
        }

        const auto candidate = process_key(process.name);
        if (candidate == expected) {
            normalized_matches.insert(process.process_id);
        } else if (!candidate.empty()
                   && (candidate.contains(expected) || expected.contains(candidate))) {
            related.push_back(process.name);
        }
    }

    const auto select = [&](const std::set<std::uint32_t>& matches,
                            const bool exact) -> std::uint32_t {
        if (matches.size() == 1) {
            return *matches.begin();
        }

        std::set<std::uint32_t> live;

        for (const auto process_id : matches) {
            const auto modules = memory.modules(process_id);
            if (!modules) {
                continue;
            }

            const auto found = std::ranges::any_of(*modules, [&](const auto& module) {
                return exact ? lower(base_name(module.name)) == exact_name
                             : process_key(module.name) == expected;
            });

            if (found) {
                live.insert(process_id);
            }
        }

        if (live.size() == 1) {
            return *live.begin();
        }

        const auto& candidates = live.empty() ? matches : live;
        auto message = std::string{"multiple live guest processes match; candidate PIDs:"};

        for (const auto process_id : candidates) {
            message += " " + std::to_string(process_id);
        }

        message += "; use --pid <pid>";
        throw std::runtime_error(message);
    };

    if (!exact_matches.empty()) {
        return select(exact_matches, true);
    }

    if (!normalized_matches.empty()) {
        return select(normalized_matches, false);
    }

    if (related.size() == 1) {
        const auto found = std::ranges::find_if(
            *processes, [&](const auto& process) {
                return process.name == related.front();
            });

        if (found != processes->end()) {
            return found->process_id;
        }
    }

    auto message = std::string{"target process was not found; normalized target: "} + expected;

    if (!related.empty()) {
        message += "; related guest names:";

        for (const auto& name : related) {
            message += " " + name;
        }
    }

    throw std::runtime_error(message);
}

std::string find_process(kvmlib::MemProcFs& memory, const std::uint32_t process_id) {
    if (!memory.refresh()) {
        throw std::runtime_error("unable to refresh the guest process list");
    }
    const auto processes = memory.processes();
    if (!processes) {
        throw std::runtime_error("unable to enumerate guest processes");
    }

    const auto found = std::ranges::find_if(
        *processes, [&](const auto& process) {
            return process.process_id == process_id;
        });

    if (found == processes->end()) {
        throw std::runtime_error("the requested PID is not present in the guest process list");
    }

    return found->name;
}

const kvmlib::ModuleInfo& find_module(const std::vector<kvmlib::ModuleInfo>& modules,
                                      const std::string_view name) {
    const auto expected = lower(base_name(name));
    const auto found = std::ranges::find_if(modules, [&](const auto& module) {
        return lower(base_name(module.name)) == expected
            || lower(base_name(module.path)) == expected;
    });

    if (found == modules.end()) {
        throw std::runtime_error("the exact main module is not visible in the target process");
    }

    return *found;
}

bool read_complete(kvmlib::MemProcFs& memory,
                   const std::uint32_t process_id,
                   const std::uint64_t address,
                   const std::span<std::byte> bytes) {
    std::size_t complete{};

    for (int attempt{}; attempt < 4 && complete < bytes.size(); ++attempt) {
        const auto result = memory.read(process_id, address + complete, bytes.subspan(complete));

        if (result && *result) {
            complete += (std::min)(*result, bytes.size() - complete);
        }
    }

    return complete == bytes.size();
}

int probe_dtb(kvmlib::MemProcFs& memory,
              const std::uint32_t process_id,
              const kvmlib::ModuleInfo& module,
              const std::uint64_t dtb) {
    if (!memory.force_process_dtb(process_id, dtb)) {
        return -1;
    }

    std::array<std::byte, 0x1000> header{};
    if (!read_complete(memory, process_id, module.base, header)) {
        return -1;
    }

    ImageInfo info;
    try {
        info = inspect_pe_image(header);
    } catch (...) {
        return -1;
    }

    if (module.image_size && info.image_size != module.image_size) {
        return -1;
    }

    const auto entry = module.base + info.entry;
    std::array<std::byte, 64> sample{};

    if (!read_complete(memory, process_id, entry, sample)) {
        return -1;
    }

    int score = 16;
    const std::array<std::uint32_t, 3> probes{
        info.image_size / 4,
        info.image_size / 2,
        info.image_size - (std::min)(info.image_size, static_cast<std::uint32_t>(sample.size()))};

    for (const auto offset : probes) {
        if (read_complete(memory, process_id, module.base + offset, sample)) {
            ++score;
        }
    }

    return score;
}

std::uint64_t resolve_dtb(kvmlib::MemProcFs& memory,
                          const std::uint32_t process_id,
                          const kvmlib::ModuleInfo& module) {
    const auto process = memory.process_info(process_id);
    if (!process) {
        throw std::runtime_error("unable to read target process metadata");
    }

    std::unordered_map<std::uint64_t, std::size_t> candidates;

    const auto add = [&](std::uint64_t value) {
        value &= cr3_mask;
        if (value >= 0x100000 && (candidates.size() < 4096 || candidates.contains(value))) {
            ++candidates[value];
        }
    };

    add(process->dtb);
    add(process->user_dtb);

    auto trace = kvmlib::Cr3Trace::open();
    if (!trace) {
        throw std::runtime_error("unable to open /dev/kvm_cr3trace");
    }

    if (!trace->start()) {
        throw std::runtime_error("unable to arm CR3 interception");
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < deadline) {
        const auto events = trace->poll();
        if (!events) {
            throw std::runtime_error("CR3 interception failed while polling");
        }

        for (const auto& event : *events) {
            add(event.current);
            add(event.previous);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    if (!trace->stop()) {
        throw std::runtime_error("unable to disarm CR3 interception");
    }

    std::vector<std::pair<std::uint64_t, std::size_t>> ranked(candidates.begin(), candidates.end());
    std::ranges::sort(ranked, [](const auto& left, const auto& right) {
        return left.second > right.second;
    });

    int best_score = -1;
    std::uint64_t best{};

    for (const auto [candidate, frequency] : ranked) {
        static_cast<void>(frequency);
        const auto score = probe_dtb(memory, process_id, module, candidate);
        if (score > best_score) {
            best_score = score;
            best = candidate;
        }
    }

    if (!best || best_score < 16 || !memory.force_process_dtb(process_id, best)) {
        throw std::runtime_error("no intercepted CR3 maps the target headers and entry point");
    }

    return best;
}

struct Capture {
    std::vector<std::byte> image;
    std::vector<std::size_t> page_bytes;
    std::size_t pages{};
    std::size_t retries{};
    std::size_t nonresident_data_pages{};
};

Capture capture_image(kvmlib::MemProcFs& memory,
                      const std::uint32_t process_id,
                      const kvmlib::ModuleInfo& module) {
    const auto header_count =
        (std::min)(static_cast<std::size_t>(module.image_size), std::size_t{0x10000});
    if (header_count < page_size) {
        throw std::runtime_error("target module is too small to be a valid PE image");
    }

    std::vector<std::byte> header(header_count);
    if (!read_complete(memory, process_id, module.base, header)) {
        throw std::runtime_error("unable to read complete target PE headers");
    }

    const auto info = inspect_pe_image(header);
    if (module.image_size && info.image_size != module.image_size) {
        throw std::runtime_error("module size does not match the PE header");
    }

    Capture capture{std::vector<std::byte>(info.image_size),
                    {},
                    (info.image_size + page_size - 1) / page_size,
                    0,
                    0};
    capture.page_bytes.resize(capture.pages);
    auto& complete = capture.page_bytes;
    std::vector<bool> requested(capture.pages, true);
    std::vector<bool> mandatory(capture.pages);

    const auto mark =
        [&](std::vector<bool>& pages, const std::uint32_t offset, const std::uint32_t size) {
            if (!size) {
                return;
            }

            const auto first = static_cast<std::size_t>(offset) / page_size;
            const auto last = (static_cast<std::size_t>(offset) + size - 1) / page_size;

            for (auto index = first; index <= last && index < pages.size(); ++index) {
                pages[index] = true;
            }
        };

    mark(requested, 0, info.headers_size);
    mark(mandatory, 0, info.headers_size);

    for (const auto& section : info.sections) {
        const auto size = section.virtual_size ? section.virtual_size : section.raw_size;
        if (section.characteristics & (section_code | section_executable)) {
            mark(mandatory, section.virtual_address, size);
        }
    }

    const std::array<std::size_t, 8> critical_directories{0, 1, 3, 6, 9, 10, 12, 13};

    for (const auto index : critical_directories) {
        if (index >= info.directories.size()) {
            continue;
        }

        const auto& directory = info.directories[index];
        mark(requested, directory.virtual_address, directory.size);
        mark(mandatory, directory.virtual_address, directory.size);
    }

    constexpr std::size_t batch_size = 256;

    for (std::size_t begin{}; begin < capture.pages; begin += batch_size) {
        const auto end = (std::min)(capture.pages, begin + batch_size);
        std::vector<kvmlib::MemoryTransfer> transfers;
        transfers.reserve(end - begin);

        for (std::size_t index = begin; index < end; ++index) {
            const auto offset = index * page_size;
            const auto count = (std::min)(page_size, capture.image.size() - offset);
            transfers.push_back(
                {module.base + offset, std::span{capture.image}.subspan(offset, count), 0});
        }

        [[maybe_unused]] const auto scatter_result = memory.scatter_read(process_id, transfers);

        for (std::size_t index{}; index < transfers.size(); ++index) {
            complete[begin + index] = transfers[index].bytes_read;
        }

        const auto percent =
            capture.pages ? static_cast<unsigned>((end * 90) / capture.pages) : 90u;
        std::cout << "\rDumping image: " << percent << "%" << std::flush;
    }

    for (std::size_t index{}; index < capture.pages; ++index) {
        const auto offset = index * page_size;
        const auto count = (std::min)(page_size, capture.image.size() - offset);

        for (int attempt{}; attempt < 3 && complete[index] < count; ++attempt) {
            ++capture.retries;
            const auto done = complete[index];
            const auto result =
                memory.read(process_id,
                            module.base + offset + done,
                            std::span{capture.image}.subspan(offset + done, count - done));
            if (result && *result) {
                complete[index] += (std::min)(*result, count - done);
            }
        }

        if ((index & 0xff) == 0 || index + 1 == capture.pages) {
            const auto percent = capture.pages
                ? 90u + static_cast<unsigned>(((index + 1) * 10) / capture.pages)
                : 100u;
            std::cout << "\rDumping image: " << percent << "%" << std::flush;
        }
    }

    std::cout << '\n';
    std::size_t incomplete{};
    std::map<std::string, std::size_t> incomplete_sections;

    for (std::size_t index{}; index < complete.size(); ++index) {
        if (!requested[index] || !mandatory[index]) {
            continue;
        }

        const auto offset = index * page_size;
        if (complete[index] == (std::min)(page_size, capture.image.size() - offset)) {
            continue;
        }

        ++incomplete;
        const auto found = std::ranges::find_if(info.sections, [&](const auto& section) {
            const auto size = section.virtual_size ? section.virtual_size : section.raw_size;
            return offset >= section.virtual_address
                && offset < static_cast<std::uint64_t>(section.virtual_address) + size;
        });
        ++incomplete_sections[found == info.sections.end() ? "headers" : found->name];
    }

    if (incomplete) {
        auto message = std::string{"required PE pages remained incomplete after retries:"};

        for (const auto& [section, count] : incomplete_sections) {
            message += " " + section + "=" + std::to_string(count);
        }

        throw std::runtime_error(message);
    }

    for (std::size_t index{}; index < complete.size(); ++index) {
        if (!requested[index] || mandatory[index]) {
            continue;
        }

        const auto offset = index * page_size;
        if (complete[index] != (std::min)(page_size, capture.image.size() - offset)) {
            ++capture.nonresident_data_pages;
        }
    }

    return capture;
}

std::string output_stem(const std::string_view process_name) {
    auto name = base_name(process_name);

    for (auto& character : name) {
        const auto value = static_cast<unsigned char>(character);
        if (!std::isalnum(value) && character != '.' && character != '_' && character != '-') {
            character = '_';
        }
    }

    if (lower(std::filesystem::path(name).extension().string()) == ".exe") {
        name.resize(name.size() - 4);
    }

    if (name.empty()) {
        throw std::runtime_error("target process name cannot form an output filename");
    }

    return name;
}

void save(const std::filesystem::path& path, const std::span<const std::byte> bytes) {
    auto temporary = path;
    temporary += ".tmp";

    std::error_code error;
    std::filesystem::remove(temporary, error);

    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);

        if (!file) {
            throw std::runtime_error("unable to create temporary output file");
        }

        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        file.close();

        if (!file) {
            std::filesystem::remove(temporary, error);
            throw std::runtime_error("unable to write complete output file");
        }
    }

    std::filesystem::rename(temporary, path, error);

    if (error) {
        std::filesystem::remove(temporary, error);
        throw std::runtime_error("unable to atomically publish output file");
    }
}

int dump_target(kvmlib::MemProcFs& memory,
                const std::uint32_t process_id,
                const std::string_view process_name,
                const std::string_view device) {
    auto modules = memory.modules(process_id);
    if (!modules) {
        throw std::runtime_error("unable to enumerate target modules");
    }

    const auto initial_module = find_module(*modules, process_name);
    const auto module_name = initial_module.name;
    const auto dtb = resolve_dtb(memory, process_id, initial_module);
    const auto directory = std::filesystem::current_path() / "dumps";
    std::filesystem::create_directories(directory);

    const auto stem = output_stem(process_name);
    QmpFreeze freeze(qmp_path_from_device(device));

    std::cout << "Pausing VM for a consistent image capture...\n";
    freeze.freeze();

    modules = memory.modules(process_id);
    if (!modules) {
        throw std::runtime_error("unable to enumerate modules under the resolved CR3");
    }

    const auto module = find_module(*modules, module_name);
    auto capture = capture_image(memory, process_id, module);

    std::size_t recovered{};
    const auto imports = recover_imports(
        capture.image, module.base, memory, process_id, *modules, module.base, recovered);
    freeze.resume();

    std::cout << "VM resumed. Fixing the PE...\n";
    const auto resource_recovery =
        recover_file_backed_resources(capture.image, capture.page_bytes, page_size, module.name);
    auto reconstruction =
        reconstruct_pe(std::move(capture.image), module.base, module.entry, imports, recovered);
    const auto path = directory / (stem + "_runtime.exe");
    save(path, reconstruction.file);

    std::cout << "PID: " << process_id << '\n';
    std::cout << "CR3: 0x" << std::hex << dtb << std::dec << '\n';
    std::cout << "Image pages: " << capture.pages << '\n';
    std::cout << "Mandatory pages: complete\n";
    std::cout << "Page retry attempts: " << capture.retries << '\n';
    if (resource_recovery.bytes) {
        std::cout << "File-backed resources: " << resource_recovery.bytes << " bytes across "
                  << resource_recovery.pages << " pages\n";
        std::cout << "Resource source: " << resource_recovery.source.string() << '\n';
    }

    std::cout << "Incomplete non-mandatory image pages: " << capture.nonresident_data_pages
              << " (unavailable bytes remain zero-filled)\n";
    std::cout << "Imports: " << reconstruction.imports << " in " << reconstruction.import_groups
              << " groups\n";
    std::cout << "Code-reference imports: " << reconstruction.recovered_imports << '\n';
    std::cout << "Relocations: " << reconstruction.relocation_status << '\n';
    std::cout << "Exceptions: " << reconstruction.exception_entries << " valid entries";
    if (reconstruction.dropped_exception_entries) {
        std::cout << ", " << reconstruction.dropped_exception_entries << " invalid entries dropped";
    }

    std::cout << '\n';
    std::cout << "Output: " << path.string() << '\n';

    return 0;
}

int probe_target(kvmlib::MemProcFs& memory,
                 const std::uint32_t process_id,
                 const std::string_view process_name) {
    auto modules = memory.modules(process_id);
    if (!modules) {
        throw std::runtime_error("unable to enumerate target modules");
    }

    const auto initial_module = find_module(*modules, process_name);
    const auto module_name = initial_module.name;
    const auto dtb = resolve_dtb(memory, process_id, initial_module);

    modules = memory.modules(process_id);
    if (!modules) {
        throw std::runtime_error("unable to enumerate modules under the resolved CR3");
    }

    const auto module = find_module(*modules, module_name);
    const auto header_size =
        (std::min)(static_cast<std::size_t>(module.image_size), std::size_t{0x10000});
    std::vector<std::byte> header(header_size);

    if (header_size < page_size || !read_complete(memory, process_id, module.base, header)) {
        throw std::runtime_error("unable to read complete target PE headers");
    }

    const auto info = inspect_pe_image(header);
    if (module.image_size && info.image_size != module.image_size) {
        throw std::runtime_error("module size does not match the PE header");
    }

    std::array<std::byte, 64> entry{};
    const auto live_entry = module.base + info.entry;
    if (!read_complete(memory, process_id, live_entry, entry)) {
        throw std::runtime_error("unable to read the live entry point");
    }

    std::cout << "PID: " << process_id << '\n';
    std::cout << "CR3: 0x" << std::hex << dtb << '\n';
    std::cout << "Module base: 0x" << module.base << '\n';
    std::cout << "Module size: 0x" << info.image_size << '\n';
    std::cout << "DOS signature: MZ (0x5a4d)\n";
    std::cout << "NT signature: PE (0x00004550)\n";
    std::cout << "Format: " << (info.is_64 ? "PE32+" : "PE32") << '\n';
    std::cout << "Preferred image base: 0x" << info.image_base << '\n';
    std::cout << "Entry RVA: 0x" << info.entry << '\n';
    std::cout << "Live entry: 0x" << live_entry << '\n';
    std::cout << "Sections: " << std::dec << info.sections.size() << '\n';
    for (const auto& section : info.sections) {
        std::cout << section.name << " RVA=0x" << std::hex << section.virtual_address
                  << " virtual=0x" << section.virtual_size << " raw=0x" << section.raw_size
                  << " characteristics=0x" << section.characteristics << '\n';
    }

    return 0;
}

} // namespace

int run(const std::string_view process_name) {
    std::string last_error;

    for (const auto& device : qemu_devices()) {
        auto opened = kvmlib::MemProcFs::open({.device = device,
                                               .wait_initialize = true,
                                               .refresh_mode = kvmlib::RefreshMode::manual,
                                               .log_file = {},
                                               .log_level = {}});
        if (!opened) {
            last_error = "unable to initialize MemProcFS for a running QEMU guest";
            continue;
        }

        auto memory = std::move(*opened);
        std::uint32_t process_id{};

        try {
            process_id = find_process(memory, process_name);
        } catch (const std::runtime_error& error) {
            last_error = error.what();
            continue;
        }

        return dump_target(memory, process_id, process_name, device);
    }

    throw std::runtime_error(
        last_error.empty() ? "target process was not found in any running KVM guest" : last_error);
}

int run(const std::uint32_t requested_process_id) {
    std::string last_error;

    for (const auto& device : qemu_devices()) {
        auto opened = kvmlib::MemProcFs::open({.device = device,
                                               .wait_initialize = true,
                                               .refresh_mode = kvmlib::RefreshMode::manual,
                                               .log_file = {},
                                               .log_level = {}});
        if (!opened) {
            last_error = "unable to initialize MemProcFS for a running QEMU guest";
            continue;
        }

        auto memory = std::move(*opened);

        try {
            const auto process_name = find_process(memory, requested_process_id);
            return dump_target(memory, requested_process_id, process_name, device);
        } catch (const std::runtime_error& error) {
            last_error = error.what();
        }
    }

    throw std::runtime_error(last_error.empty()
                                 ? "the requested PID was not found in any running KVM guest"
                                 : last_error);
}

int probe(const std::string_view process_name) {
    std::string last_error;

    for (const auto& device : qemu_devices()) {
        auto opened = kvmlib::MemProcFs::open({.device = device,
                                               .wait_initialize = true,
                                               .refresh_mode = kvmlib::RefreshMode::manual,
                                               .log_file = {},
                                               .log_level = {}});
        if (!opened) {
            last_error = "unable to initialize MemProcFS for a running QEMU guest";
            continue;
        }

        auto memory = std::move(*opened);
        std::uint32_t process_id{};

        try {
            process_id = find_process(memory, process_name);
        } catch (const std::runtime_error& error) {
            last_error = error.what();
            continue;
        }

        return probe_target(memory, process_id, process_name);
    }

    throw std::runtime_error(
        last_error.empty() ? "target process was not found in any running KVM guest" : last_error);
}

} // namespace runtime_dumper
