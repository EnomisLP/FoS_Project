#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Class to establish and manage a secure TLS channel with PFS
class secureChannel {
public:
    secureChannel();
    ~secureChannel();

    bool initClientContext(const std::string& ca_cert_path);
    bool connectToServer(const std::string& host, int port);
    bool sendData(const std::string& data);
    std::string receiveData();

private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;

    bool createSocket(const std::string& host, int port);
};
