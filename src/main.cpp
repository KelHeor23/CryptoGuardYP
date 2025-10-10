#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <iostream>
#include <print>
#include <fstream>

int main(int argc, char *argv[]) {
    try {     
        CryptoGuard::ProgramOptions options;

        options.Parse(argc, argv);

        if (options.isHelpRequested()) {
            options.printHelp();
            return 0;
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in);
            if (!inputFile.is_open())
                throw std::runtime_error("Error opening file inputFile");
            std::fstream outputFile(options.GetOutputFile(), std::ios::out);
            if (!outputFile.is_open())
                throw std::runtime_error("Error opening file outputFile");

            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in);
            if (!inputFile.is_open())
                throw std::runtime_error("Error opening file inputFile");
            std::fstream outputFile(options.GetOutputFile(), std::ios::out);
            if (!outputFile.is_open())
                throw std::runtime_error("Error opening file outputFile");

            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }
        case COMMAND_TYPE::CHECKSUM: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in);
            if (!inputFile.is_open())
                throw std::runtime_error("Error opening file inputFile");

            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputFile));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}