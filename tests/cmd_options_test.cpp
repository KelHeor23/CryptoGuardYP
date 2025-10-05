#include <gtest/gtest.h>

#include "cmd_options.h"

TEST(ProgramOptions, ParsesAllRequiredOptionsSuccessfully) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "--command",    "encrypt",
        "--input",      "input.txt",
        "--output",     "output.txt",
        "--password",   "mypassword"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_TRUE(options.Parse(argc, const_cast<char**>(argv)));
    EXPECT_FALSE(options.isHelpRequested());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(),   "input.txt");
    EXPECT_EQ(options.GetOutputFile(),  "output.txt");
    EXPECT_EQ(options.GetPassword(),    "mypassword");
}

TEST(ProgramOptions, ParsesAllShortRequiredOptionsSuccessfully) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "-c", "encrypt",
        "-i", "input.txt",
        "-o", "output.txt",
        "-p", "mypassword"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_TRUE(options.Parse(argc, const_cast<char**>(argv)));
    EXPECT_FALSE(options.isHelpRequested());
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(),   "input.txt");
    EXPECT_EQ(options.GetOutputFile(),  "output.txt");
    EXPECT_EQ(options.GetPassword(),    "mypassword");
}

TEST(ProgramOptions, ParsesCallForHelpSuccessful) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "-h"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_TRUE(options.Parse(argc, const_cast<char**>(argv)));
    EXPECT_TRUE(options.isHelpRequested());
}

TEST(ProgramOptions, ParsesMissingRequiredOptionsFailed) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "-c", "encrypt",
        "-i", "input.txt",
        "-o", "output.txt"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_FALSE(options.Parse(argc, const_cast<char**>(argv)));
}

TEST(ProgramOptions, ParsesInvalidCommandValueFailed) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "--command",    "error_value",
        "--input",      "input.txt",
        "--output",     "output.txt",
        "--password",   "mypassword"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_FALSE(options.Parse(argc, const_cast<char**>(argv)));
}

TEST(ProgramOptions, ParsesUnknownOptionsFailed) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {
        "CryptoGuard",
        "--command",        "error_value",
        "--input",          "input.txt",
        "--output",         "output.txt",
        "--password",       "mypassword",
        "--errorOption",    "mypassword"
    };

    int argc = sizeof(argv) / sizeof(argv[0]);
    EXPECT_FALSE(options.Parse(argc, const_cast<char**>(argv)));
}