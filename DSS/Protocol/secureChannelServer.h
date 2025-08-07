#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

class secureChannelServer {
public:
    secureChannelServer();
    ~secureChannelServer();

    bool initServerContext(const std::string& cert_path, const std::string& key_path, const std::string& ca_cert_path);
    bool bindAndListen(int port);
    bool acceptClient();
    bool sendData(const std::string& data);
    std::string receiveData();

private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    int client_fd;

    bool createServerSocket(int port);
};
