#pragma once

#include <cstdint>
#include <string_view>

namespace runtime_dumper {

int run(std::string_view process_name);
int run(std::uint32_t process_id);
int probe(std::string_view process_name);

} // namespace runtime_dumper
