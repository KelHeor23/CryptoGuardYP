#include <iostream>

#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "Show help")
        ("command,c",   po::value<COMMAND_TYPE>(&command_)->required(),     "Select command: encrypt, decrypt, checksum")
        ("input,i",     po::value<std::string>(&inputFile_)->required(),    "Path to the input file")
        ("output,o",    po::value<std::string>(&outputFile_)->required(),   "Path to the output file")
        ("password,p",  po::value<std::string>(&password_)->required(),     "Password for encryption and decryption");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {        
        po::store(po::parse_command_line(argc, argv, desc_), vm_);        

        if (vm_.count("help")) {
            std::cout << desc_ << "\n";
            helpRequested_ = true;
            return true;
        }

        po::notify(vm_);
    } 
    catch (const po::error &e) {
        std::print(std::cerr, "Error parsing command line: {}\n", e.what());
        return false;
    } catch (...) {
        std::print(std::cerr, "Error parsing command line: {}\n", "Something unexpected happened");
        return false;
    }
    return true;
}

}  // namespace CryptoGuard
