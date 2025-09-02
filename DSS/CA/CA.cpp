#include "CA.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <ctime>
#include <fstream>
#include <iostream>

CA::CA(const std::string& keyPath, const std::string& certPath)
    : caKeyPath(keyPath), caCertPath(certPath), caKey(nullptr), caCert(nullptr) {}

bool CA::init() {
    FILE* f = fopen(caKeyPath.c_str(), "r");
    if (f) {
        caKey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        fclose(f);
    }
    f = fopen(caCertPath.c_str(), "r");
    if (f) {
        caCert = PEM_read_X509(f, nullptr, nullptr, nullptr);
        fclose(f);
    }

    if (!caKey || !caCert) {
        caKey = generateKeyPair();
        caCert = generateRootCertificate(caKey);

        FILE* keyOut = fopen(caKeyPath.c_str(), "w");
        PEM_write_PrivateKey(keyOut, caKey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(keyOut);

        FILE* certOut = fopen(caCertPath.c_str(), "w");
        PEM_write_X509(certOut, caCert);
        fclose(certOut);
    }

    return caKey && caCert;
}
EVP_PKEY* CA::generateKeyPair() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);

    if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) {
        std::cerr << "[CA] RSA key generation failed\n";
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        BN_free(bn);
        return nullptr;
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn); 
    return pkey;
}

X509* CA::generateRootCertificate(EVP_PKEY* pkey) {
    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60L*60L*24L*3650);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)"DSS Root CA", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_sign(x509, pkey, EVP_sha256());
    return x509;
}

std::string CA::signCSR(const std::string& csrPem, int daysValid) {
    BIO* bio = BIO_new_mem_buf(csrPem.data(), csrPem.size());
    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!req) return "";

    EVP_PKEY* reqKey = X509_REQ_get_pubkey(req);
    X509* cert = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(cert), std::time(nullptr));
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60L*60L*24L*daysValid);

    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    X509_set_pubkey(cert, reqKey);

    X509_sign(cert, caKey, EVP_sha256());

    std::string pem = certToPEM(cert);

    EVP_PKEY_free(reqKey);
    X509_REQ_free(req);
    X509_free(cert);

    return pem;
}

std::string CA::certToPEM(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem(data, len);

    BIO_free(bio);
    return pem;
}
