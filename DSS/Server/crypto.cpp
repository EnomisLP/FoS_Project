
#include "crypto.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <vector>
#include <cstring>
#include <iostream>

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

// Generate RSA key pair, return pub/encrypted-priv
std::pair<std::string, std::string> crypto::CreateKeys(const std::string& password) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) {
        std::cerr << "Key generation error.\n";
        return {};
    }

    BIO* priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char* priv_data;
    long priv_len = BIO_get_mem_data(priv, &priv_data);
    std::string priv_pem(priv_data, priv_len);

    BIO* pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(pub, rsa);
    char* pub_data;
    long pub_len = BIO_get_mem_data(pub, &pub_data);
    std::string pub_pem(pub_data, pub_len);

    BIO_free_all(priv);
    BIO_free_all(pub);
    RSA_free(rsa);
    BN_free(bn);

    std::string encrypted_priv = encrypt_private_key(priv_pem, password);
    return {pub_pem, encrypted_priv};
}

// Sign document using encrypted private key
std::string crypto::SignDoc(const std::string& encrypted_priv_key, const std::string& password, const std::string& document) {
    std::string priv_key_pem = decrypt_private_key(encrypted_priv_key, password);
    BIO* bio = BIO_new_mem_buf(priv_key_pem.data(), priv_key_pem.size());
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsa) {
        std::cerr << "Invalid private key.\n";
        return "";
    }

    std::vector<unsigned char> sig(RSA_size(rsa));
    unsigned int sig_len;

    if (!RSA_sign(NID_sha256,
                  reinterpret_cast<const unsigned char*>(document.data()), document.size(),
                  sig.data(), &sig_len, rsa)) {
        std::cerr << "Signing failed.\n";
        RSA_free(rsa);
        return "";
    }

    RSA_free(rsa);
    return std::string(reinterpret_cast<char*>(sig.data()), sig_len);
}

// Return placeholder public key
std::string crypto::GetPublicKey(const std::string& username) {
    return "PUBLIC_KEY_FOR_" + username;
}
