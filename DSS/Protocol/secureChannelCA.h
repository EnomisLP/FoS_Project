#pragma once
#include <string>
#include <openssl/ssl.h>
#include <openssl/x509.h>

class secureChannelCA {
private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    int client_fd;
// Returns the current SSL connection pointer (nullptr if not connected)

public:
    // Constructor and Destructor
    secureChannelCA();
    ~secureChannelCA();
    SSL* getSSL() const;
    // Server initialization and connection
    bool initCAContext(const std::string& caCertPath,
                       const std::string& serverKeyPath,
                       const std::string& serverCertPath);
    bool createSocket(int port);
    bool bindAndListen(int port);
    bool acceptConnection();

    // Communication methods
    bool sendData(const std::string& data);
    std::string receiveData();
    
    // Certificate verification
    bool authenticateCAWithCertificate(const std::string& trustedCertPath);
    std::string getServerPublicKey();
};