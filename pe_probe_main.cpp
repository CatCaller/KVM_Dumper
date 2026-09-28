#include "runtime_dump.h"

#include <exception>
#include <iostream>
#include <string_view>

int main(const int count, char** values) {
    if (count != 2) {
        std::cerr << "usage: sudo ./pe_probe <process-name>\n";
        return 2;
    }

    try {
        return runtime_dumper::probe(std::string_view{values[1]});
    } catch (const std::exception& error) {
        std::cerr << "pe_probe: " << error.what() << '\n';
        return 1;
    }
}
