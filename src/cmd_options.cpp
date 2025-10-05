#include <iostream>

#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "Show help");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    try {        
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm_);
        boost::program_options::notify(vm_);

        if (vm_.count("help")) {
            std::cout << desc_ << "\n";
            helpRequested_ = true;
            return;
        }
    } 
    catch (const boost::program_options::error &ex) {
        throw std::runtime_error(std::string("Error parsing command line: ") + ex.what());
    } catch (...) {
        throw std::runtime_error("Something unexpected happened");
    }
    return;
}

}  // namespace CryptoGuard
