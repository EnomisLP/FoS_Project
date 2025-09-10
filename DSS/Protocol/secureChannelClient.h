#pragma once
#include <openssl/ssl.h>
#include <string>
#include "DB/db.h"

class secureChannelClient {
public:
    secureChannelClient(db &databaseHandle);
    ~secureChannelClient();

    // Initialize SSL context
    bool initClientContext(const std::string& caCertPath, db& databaseHandle);

    // Connect to server over TCP + SSL
    bool connectToServer(const std::string& host, int port);
    std::string random_hex(int bytes);
    // Send/receive data over secure channel
    std::string receiveAndVerifyNonce(const std::string& ownerIdentifier);
    bool sendData(const std::string& data);
    std::string receiveData();
    bool connectToCA(const std::string& host, int port, const std::string& caCertPath);
    bool sendWithNonce(const std::string& owner, const std::string& payload, int ttl_seconds);
    // Manual server authentication with known public key (PEM string)
    bool authenticateServerWithCertificate(const std::string& trustedCertPath);
private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    db& databaseHandle;
    bool createSocket(const std::string& host, int port);
    std::string getServerPublicKey();
};
