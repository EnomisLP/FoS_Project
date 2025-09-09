
#include "crypto.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <vector>
#include <cstring>
#include <iostream>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <filesystem>
#include <openssl/x509_vfy.h>

// Constructor
crypto::crypto() {
    // Could be used to initialize OpenSSL or config
    OpenSSL_add_all_algorithms();
}

// AES encrypt private key
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <sstream>

std::string crypto::encrypt_private_key(const std::string& priv_key_pem, const std::string& password) {
    BIO* bio = BIO_new_mem_buf(priv_key_pem.data(), priv_key_pem.size());
    if (!bio) return "";

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        std::cerr << "[Crypto] Failed to parse private key for encryption\n";
        return "";
    }

    BIO* out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        return "";
    }

    // Encrypt with PKCS#8, AES-256-CBC
    if (!PEM_write_bio_PKCS8PrivateKey(out, pkey, EVP_aes_256_cbc(), nullptr, 0,
                                       nullptr, (void*)password.c_str())) {
        std::cerr << "[Crypto] Failed to write encrypted private key\n";
        BIO_free(out);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_free(pkey);

    char* data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string encrypted(data, len);
    BIO_free(out);

    return encrypted;
}

std::string crypto::decrypt_private_key(const std::string& encrypted_pem, const std::string& password) {
    BIO* bio = BIO_new_mem_buf(encrypted_pem.data(), encrypted_pem.size());
    if (!bio) return "";

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, (void*)password.c_str());
    BIO_free(bio);

    if (!pkey) {
        std::cerr << "[Crypto] Failed to decrypt private key (wrong password or corrupted)\n";
        return "";
    }

    BIO* out = BIO_new(BIO_s_mem());
    if (!out) {
        EVP_PKEY_free(pkey);
        return "";
    }

    if (!PEM_write_bio_PrivateKey(out, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "[Crypto] Failed to write decrypted private key PEM\n";
        BIO_free(out);
        EVP_PKEY_free(pkey);
        return "";
    }

    EVP_PKEY_free(pkey);

    char* data = nullptr;
    long len = BIO_get_mem_data(out, &data);
    std::string decrypted(data, len);
    BIO_free(out);

    return decrypted;
}


// Hash password
std::string crypto::hash_password(const std::string& password) {
unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);

    // Convert raw bytes → hex string (better than raw binary)
    std::string hexHash;
    hexHash.reserve(SHA256_DIGEST_LENGTH * 2);
    const char* hexChars = "0123456789abcdef";

    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        unsigned char b = hash[i];
        hexHash.push_back(hexChars[b >> 4]);
        hexHash.push_back(hexChars[b & 0x0F]);
    }

    return hexHash;
}
// AES decrypt private key

std::string crypto::signFile(const std::string& privKeyPem, const std::string& filePath) {
    // 1. Open the file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[Crypto] Could not open file: " << filePath << "\n";
        return "";
    }

    // 2. Read file into memory
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());

    // 3. Hash with SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(fileData.data(), fileData.size(), hash);

    // 4. Load private key (PKCS#8 safe)
    BIO* bio = BIO_new_mem_buf(privKeyPem.data(), privKeyPem.size());
    if (!bio) {
        std::cerr << "[Crypto] Failed to create BIO for private key\n";
        return "";
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) {
        std::cerr << "[Crypto] Failed to parse private key\n";
        ERR_print_errors_fp(stderr);
        return "";
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa) {
        std::cerr << "[Crypto] Private key is not RSA\n";
        return "";
    }

    // 5. Sign the hash
    std::vector<unsigned char> sig(RSA_size(rsa));
    unsigned int sigLen = 0;

    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig.data(), &sigLen, rsa) != 1) {
        std::cerr << "[Crypto] RSA_sign failed\n";
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return "";
    }
    RSA_free(rsa);

    // 6. Base64-encode the signature
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // one-line output

    BIO_write(b64, sig.data(), sigLen);
    BIO_flush(b64);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string signature(bufferPtr->data, bufferPtr->length);

    BIO_free_all(b64);

    return signature;
}
// Generate RSA key pair, return pub/encrypted-priv
std::string crypto::createCSR(const std::string& username,
                               const std::string& pubPem,
                               const std::string& privPem) 
{
    // 1) Load private key from PEM string
    BIO* privBio = BIO_new_mem_buf(privPem.data(), privPem.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(privBio, nullptr, nullptr, nullptr);
    BIO_free(privBio);
    if (!pkey) {
        std::cerr << "[CRYPTO] Failed to load private key for CSR\n";
        return "";
    }

    // 2) Create new CSR
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        return "";
    }

    // 3) Set public key in CSR
    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return "";
    }

    // 4) Set subject name
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(username.c_str()), -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // 5) Sign CSR with private key
    if (X509_REQ_sign(req, pkey, EVP_sha256()) <= 0) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return "";
    }

    // 6) Convert CSR to PEM string
    BIO* csrBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(csrBio, req);
    BUF_MEM* csrBuf;
    BIO_get_mem_ptr(csrBio, &csrBuf);
    std::string csrPem(csrBuf->data, csrBuf->length);

    // Cleanup
    BIO_free(csrBio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return csrPem;
}

bool crypto::verifyCertificate(const std::string& certPem) {
    // Load cert to verify
    BIO* bio = BIO_new_mem_buf(certPem.data(), certPem.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        std::cerr << "[Crypto] Failed to parse certificate\n";
        return false;
    }

    // Load CA cert (the one used to sign the CSR)
    BIO* caBio = BIO_new_file("/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.crt", "r");
    if (!caBio) {
        std::cerr << "[Crypto] Failed to open CA cert file\n";
        X509_free(cert);
        return false;
    }
    X509* caCert = PEM_read_bio_X509(caBio, nullptr, nullptr, nullptr);
    BIO_free(caBio);
    if (!caCert) {
        std::cerr << "[Crypto] Failed to read CA cert\n";
        X509_free(cert);
        return false;
    }

    // Verify signature
    EVP_PKEY* caPubKey = X509_get_pubkey(caCert);
    bool valid = X509_verify(cert, caPubKey) == 1;
    EVP_PKEY_free(caPubKey);

    X509_free(cert);
    X509_free(caCert);

    return valid;
}




std::pair<std::string, std::string> crypto::generateKeypair() {
    // 1) Generate RSA key pair
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) {
        std::cerr << "[CRYPTO] Key generation error\n";
        return {};
    }

    // 2) Write private key to PEM in memory
    BIO* privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(privBio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char* privData;
    long privLen = BIO_get_mem_data(privBio, &privData);
    std::string privPem(privData, privLen);

    // 3) Write public key to PEM in memory
    BIO* pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pubBio, rsa);
    char* pubData;
    long pubLen = BIO_get_mem_data(pubBio, &pubData);
    std::string pubPem(pubData, pubLen);

    // Cleanup
    BIO_free_all(privBio);
    BIO_free_all(pubBio);
    RSA_free(rsa);
    BN_free(bn);

    return {pubPem, privPem};
}
std::string crypto::extractPublicKey(const std::string& certPem) {
    BIO* bio = BIO_new_mem_buf(certPem.data(), certPem.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return "";

    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    if (!pubKey) {
        X509_free(cert);
        return "";
    }

    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(out, pubKey);

    char* data;
    long len = BIO_get_mem_data(out, &data);
    std::string pubKeyPem(data, len);

    EVP_PKEY_free(pubKey);
    BIO_free(out);
    X509_free(cert);

    return pubKeyPem;
}

// Sign document using encrypted private key


