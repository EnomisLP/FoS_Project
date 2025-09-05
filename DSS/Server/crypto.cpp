
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

// Constructor
crypto::crypto() {
    // Could be used to initialize OpenSSL or config
    OpenSSL_add_all_algorithms();
}

// AES encrypt private key
std::string crypto::encrypt_private_key(const std::string& priv_key, const std::string& password) {
    unsigned char key[16], iv[16];
    memset(key, 0, 16);
    memset(iv, 0, 16);
    strncpy((char*)key, password.c_str(), 16);

    std::vector<unsigned char> ciphertext(priv_key.size() + AES_BLOCK_SIZE);
    int outlen1, outlen2;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1, reinterpret_cast<const unsigned char*>(priv_key.data()), priv_key.size());
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(ciphertext.data()), outlen1 + outlen2);
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
std::string crypto::decrypt_private_key(const std::string& encrypted, const std::string& password) {
    unsigned char key[16], iv[16];
    memset(key, 0, 16);
    memset(iv, 0, 16);
    strncpy((char*)key, password.c_str(), 16);

    std::vector<unsigned char> plaintext(encrypted.size());
    int outlen1, outlen2;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1, reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size());
    EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), outlen1 + outlen2);
}
std::string crypto::signFile(const std::string& privKeyPem, const std::string& filePath) {
    // 1. Open the file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";

    // 2. Read entire file into memory
    std::vector<unsigned char> fileData((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());

    // 3. Hash the data (SHA-256)
    unsigned char hash[32];
    SHA256(fileData.data(), fileData.size(), hash);

    // 4. Load private key
    BIO* bio = BIO_new_mem_buf(privKeyPem.data(), privKeyPem.size());
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) return "";

    // 5. Sign hash
    unsigned char sig[256];
    unsigned int sigLen = 0;
    if (RSA_sign(NID_sha256, hash, 32, sig, &sigLen, rsa) != 1) {
        RSA_free(rsa);
        return "";
    }

    RSA_free(rsa);

    // 6. Return signature as string
    return std::string(reinterpret_cast<char*>(sig), sigLen);
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

bool crypto::verifyCertificate(const std::string& certPem, const std::string& caPath) {
    BIO* bio = BIO_new_mem_buf(certPem.data(), certPem.size());
    if (!bio) return false;

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) return false;

    // Load CA root (trusted anchor)
    X509_STORE* store = X509_STORE_new();
    X509_STORE_load_locations(store, caPath.c_str(), nullptr);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);

    bool result = (X509_verify_cert(ctx) == 1);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);

    return result;
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


