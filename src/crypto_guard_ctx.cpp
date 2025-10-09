#include "crypto_guard_ctx.h"

#include <openssl/evp.h>
#include <array>
#include <iostream>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

auto deleter = [](EVP_CIPHER_CTX* ctx) {
    if (ctx) EVP_CIPHER_CTX_free(ctx);
};

using UniqueCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(deleter)>;

class CryptoGuardCtx::Impl {
public:
    Impl() {}

    ~Impl() {
    }

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

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good() && !inStream.eof())
            throw std::runtime_error("Input stream not ready");
        if (!outStream.good())
            throw std::runtime_error("Output stream not ready");

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        UniqueCipherCtx ctx(EVP_CIPHER_CTX_new(), deleter);

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr,
                          params.key.data(), params.iv.data(),
                          params.encrypt)) {
            throw std::runtime_error("EVP_CipherInit_ex failed");
        }

        constexpr std::size_t CHUNK = 16;
        std::vector<unsigned char> outBuf(CHUNK + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(CHUNK);
        int outLen = 0;

        while (true) {
            inStream.read(reinterpret_cast<char*>(inBuf.data()),
                    static_cast<std::streamsize>(inBuf.size()));
            std::streamsize got = inStream.gcount();
            if (got <= 0) break;

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), 
                    &outLen, inBuf.data(), static_cast<int>(got))) {
                throw std::runtime_error("EVP_CipherUpdate failed");
            }

            if (outLen > 0) {
                outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
                if (!outStream.good()) {
                    throw std::runtime_error("write to outStream failed");
                }
            }

            if (inStream.eof()) break;
            if (!inStream.good() && !inStream.eof()) {
                throw std::runtime_error("read from inStream failed");
            }
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("EVP_CipherFinal_ex failed");
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            if (!outStream.good()) {
                throw std::runtime_error("write final block failed");
            }
        }

        outStream.flush();
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        return "NOT_IMPLEMENTED";
    }

private:

};

CryptoGuardCtx::CryptoGuardCtx() 
    : pImpl_(std::make_unique<Impl>()) {}

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
