#pragma once

#include <string>
#include <openssl/x509.h>
#include <openssl/evp.h>

class CA {
public:
    CA(const std::string& caKeyPath,
       const std::string& caCertPath);

    bool init();
    std::string signCSR(const std::string& csrPem, int daysValid = 365);
    
    std::string generateSerial();

private:
    std::string caKeyPath;
    std::string caCertPath;

    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;

    EVP_PKEY* generateKeyPair();
    X509* generateRootCertificate(EVP_PKEY* pkey);
    std::string certToPEM(X509* cert);
};
