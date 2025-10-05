#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

namespace po = boost::program_options;

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE {
        ENCRYPT,
        DECRYPT,
        CHECKSUM,
    };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }

    bool isHelpRequested() const { return helpRequested_; }
private:
    COMMAND_TYPE command_;
    friend std::istream& operator>>(std::istream& in, COMMAND_TYPE& cmd) {
        std::string token;
        in >> token;
        static const std::unordered_map<std::string, COMMAND_TYPE> mapping = {
            {"encrypt", COMMAND_TYPE::ENCRYPT},
            {"decrypt", COMMAND_TYPE::DECRYPT},
            {"checksum", COMMAND_TYPE::CHECKSUM},
        };
        auto it = mapping.find(token);
        if (it != mapping.end()) {
            cmd = it->second;
        } else {
            throw po::validation_error(po::validation_error::invalid_option_value, "command");
        }
        return in;
    }

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    po::options_description desc_;
    po::variables_map vm_;
    bool helpRequested_ = false;
};

}  // namespace CryptoGuard
