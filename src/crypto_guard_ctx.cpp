#include "crypto_guard_ctx.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <array>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

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

auto deleterMD_CTX = [](EVP_MD_CTX* ctx) {
    if (ctx) EVP_MD_CTX_free(ctx);
};

using UniqueCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, decltype(deleter)>;
using UniqueCipherMdCtx = std::unique_ptr<EVP_MD_CTX, decltype(deleterMD_CTX)>;

class CryptoGuardCtx::Impl {
public:
    Impl(std::string_view pwd) : ctx(EVP_CIPHER_CTX_new(), deleter) {
        params = CreateChiperParamsFromPassword(pwd);
    }

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

    void EncryptFile(std::iostream &inStream, std::iostream &outStream) {
        if (!inStream.good() && !inStream.eof())
            throw std::runtime_error("Input stream not ready");
        if (!outStream.good())
            throw std::runtime_error("Output stream not ready");

        params.encrypt = 1;

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr,
                          params.key.data(), params.iv.data(),
                          params.encrypt)) {
            throwOpenSSLError("EVP_CipherInit_ex failed");
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
                throwOpenSSLError("EVP_CipherUpdate failed");
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
            throwOpenSSLError("EVP_CipherFinal_ex failed");
        }

        if (outLen > 0) {
            outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            if (!outStream.good()) 
                throwOpenSSLError("write final block failed");
        }

        outStream.flush();
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream) {
        if (!inStream.good() && !inStream.eof())
            throw std::runtime_error("Input stream not ready");
        if (!outStream.good())
            throw std::runtime_error("Output stream not ready");

        params.encrypt = 0;

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr,
                          params.key.data(), params.iv.data(),
                          params.encrypt)) {
            throwOpenSSLError("EVP_CipherInit_ex failed");
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

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen,
                    inBuf.data(), static_cast<int>(got))) 
                throwOpenSSLError("EVP_CipherUpdate failed");            

            if (outLen > 0) {
                outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
                if (!outStream.good()) 
                    throw std::runtime_error("write to outStream failed");            
            }

            if (inStream.eof()) break;
            if (!inStream.good() && !inStream.eof()) {
                throw std::runtime_error("read from inStream failed");
            }
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) 
            throwOpenSSLError("EVP_CipherFinal_ex failed (bad decrypt?)");    

        if (outLen > 0) {
            outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            if (!outStream.good())
                throw std::runtime_error("write final block failed");        
        }

        outStream.flush();
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good() && !inStream.eof())
            throw std::runtime_error("Input stream not ready");
        UniqueCipherMdCtx ctxMd(EVP_MD_CTX_new(), deleterMD_CTX);

         // Инициализируем хеш-контекст с SHA-256
        if (!EVP_DigestInit_ex(ctxMd.get(), EVP_sha256(), nullptr)) 
            throw std::runtime_error("Failed to initialize digest context\n");
        
        constexpr std::size_t CHUNK = 16;
        std::vector<unsigned char> buf(CHUNK);

        while (true) {
            inStream.read(reinterpret_cast<char*>(buf.data()),
                    static_cast<std::streamsize>(buf.size()));
            std::streamsize got = inStream.gcount();
            if (got > 0) {
                if (!EVP_DigestUpdate(ctxMd.get(), buf.data(), static_cast<size_t>(got)))
                    throw std::runtime_error("Digest update failed");
            }

            if (inStream.eof()) break;
            if (!inStream.good()) 
                throw std::runtime_error("Read error while hashing stream");            
        }

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (!EVP_DigestFinal_ex(ctxMd.get(), md_value, &md_len))
            throw std::runtime_error("Digest finalization failed");

        return BytesToHex(md_value, md_len);
    }

private:
    static std::string BytesToHex(const unsigned char* data, unsigned int len) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < len; ++i) {
            oss << std::setw(2) << static_cast<unsigned int>(data[i]);
        }
        return oss.str();
    }

    // Собираю все ошщибки OpenSSL в одно сообщение
    void throwOpenSSLError(const char* prefix = nullptr) {
        std::ostringstream oss;
        if (prefix && prefix[0] != '\0') 
            oss << prefix << ": ";

        unsigned long errCode = 0;
        bool first = true;
        while ((errCode = ERR_get_error()) != 0) {
            char errBuf[256];
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            if (!first) oss << " | ";
            oss << errBuf;
            first = false;
        }

        if (first) {
            // Ошибок в очереди нет
            oss << "Unknown OpenSSL error";
        }

        throw std::runtime_error(oss.str());
    }
private:
    UniqueCipherCtx ctx;
    AesCipherParams params;
};

CryptoGuardCtx::CryptoGuardCtx(std::string_view pwd) 
    : pImpl_(std::make_unique<Impl>(pwd)) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream) {
    pImpl_->EncryptFile(inStream, outStream);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream) {
    pImpl_->DecryptFile(inStream, outStream);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    return pImpl_->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
