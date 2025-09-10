#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "DB/db.h"

class secureChannelServer {
public:
    secureChannelServer(db &databaseHandle);
    ~secureChannelServer();

    bool initServerContext(const std::string& cert_path, const std::string& key_path, const std::string& ca_cert_path, db &databaseHandle);
    bool bindAndListen(int port);
    bool acceptClient();
    bool sendData(const std::string& data);
    std::string random_hex(int bytes);
    bool sendWithDSSNonce(const std::string& owner, const std::string& payload, int ttl_seconds);
    std::string receiveData();

private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    int client_fd;
    db &databaseHandle;

    bool createServerSocket(int port);
};
