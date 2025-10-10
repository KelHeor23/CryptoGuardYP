#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <iostream>

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};
    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
        reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
        params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }
    return params;
}

std::string ref(std::string_view input, std::string_view pwd) {
        std::string output;

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword(pwd);
        params.encrypt = 1;
        auto *ctx = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        return output;
}

TEST(CryptoGuardCtx, EncryptAllSuccessfully) {
    std::stringstream inputStream;
    std::stringstream outputStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);

    std::string refStr = ref(input, password);
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    cryptoCtx.EncryptFile(inputStream, outputStream);
    std::string res = outputStream.str();

    EXPECT_EQ(res, refStr);
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadInputStream) {
    std::stringstream inputStream;
    std::stringstream outputStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);    
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    inputStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inputStream, outputStream), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptThrowsOnBadOutputStream) {
    std::stringstream inputStream;
    std::stringstream outputStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    outputStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inputStream, outputStream), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptAllSuccessfully) {
    std::stringstream inputStream;
    std::stringstream outputStream;
    std::stringstream decryptStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    cryptoCtx.EncryptFile(inputStream, outputStream);
    cryptoCtx.DecryptFile(outputStream, decryptStream);

    std::string res = decryptStream.str();

    EXPECT_EQ(res, input);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadEncryptStream) {
    std::stringstream inputStream;
    std::stringstream EncryptStream;
    std::stringstream DecryptStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    cryptoCtx.EncryptFile(inputStream, EncryptStream);

    EncryptStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.DecryptFile(EncryptStream, DecryptStream), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptThrowsOnBadDecryptStream) {
    std::stringstream inputStream;
    std::stringstream EncryptStream;
    std::stringstream DecryptStream;

    std::string input = "01234567890123456789";
    std::string password = "12341234";

    inputStream.str(input);
    CryptoGuard::CryptoGuardCtx cryptoCtx(password);

    cryptoCtx.EncryptFile(inputStream, EncryptStream);

    DecryptStream.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.DecryptFile(EncryptStream, DecryptStream), std::runtime_error);
}

static std::stringstream MakeBinStream(const std::string& bytes) {
    std::stringstream ss(std::ios::in | std::ios::out | std::ios::binary);
    ss.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    ss.clear();
    ss.seekg(0, std::ios::beg);
    return ss;
}

TEST(CryptoGuardCtx, CalculateChecksumAllSuccessfully) {
    // SHA256("abc") =
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    CryptoGuard::CryptoGuardCtx cryptoCtx("");

    const std::string kExpected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    auto ss = MakeBinStream("abc");
    const auto got = cryptoCtx.CalculateChecksum(ss);
    EXPECT_EQ(got, kExpected);
}

TEST(CryptoGuardCtx, CalculateChecksumThrowsOnBadInputStream) {
    // SHA256("abc") =
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    CryptoGuard::CryptoGuardCtx cryptoCtx("");

    const std::string kExpected =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    auto ss = MakeBinStream("abc");
    ss.setstate(std::ios::badbit);
    ASSERT_THROW(cryptoCtx.CalculateChecksum(ss), std::runtime_error);
}
