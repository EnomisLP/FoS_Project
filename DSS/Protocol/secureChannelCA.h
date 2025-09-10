#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "DB/dbCA.h"

class secureChannelCA {
private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    int client_fd;
// Returns the current SSL connection pointer (nullptr if not connected)

public:
    // Constructor and Destructor
    secureChannelCA(dbCA &databaseHandle);
    ~secureChannelCA();
    SSL* getSSL() const;
    // Server initialization and connection
    bool initCAContext(const std::string& caCertPath,
                       const std::string& serverKeyPath,
                       const std::string& serverCertPath,
                       dbCA &databaseHandle);
    bool createSocket(int port);
    bool bindAndListen(int port);
    bool acceptConnection();
    std::string random_hex(int bytes);
    // Communication methods
    bool sendWithNonce(const std::string& owner, const std::string& payload, int ttl_seconds);
    std::string receiveAndVerifyNonce(const std::string& ownerIdentifier);
    bool sendData(const std::string& data);
    std::string receiveData();
    
    // Certificate verification
    bool authenticateCAWithCertificate(const std::string& trustedCertPath);
    std::string getServerPublicKey();
    private:
    dbCA &databaseHandle;
};