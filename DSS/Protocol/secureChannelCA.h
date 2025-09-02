#pragma once
#include <openssl/ssl.h>
#include <string>

class secureChannelCA {
public:
    secureChannelCA();
    ~secureChannelCA();

    // Initialize SSL context
    bool initCAContext(const std::string& caCertPath,
                       const std::string& clientKeyPath,
                       const std::string& clientCertPath);

    // Connect to CA over TCP + SSL
    bool connectToCA(const std::string& host, int port, 
                            const std::string& caCertPath,
                            const std::string& clientKeyPath,
                            const std::string& clientCertPath);

    // Send/receive data over secure channel
    bool sendData(const std::string& data);
    std::string receiveData();

    // Manual server authentication with known public key (PEM string)
    bool authenticateCAWithCertificate(const std::string& trustedCertPath);
    bool createSocket(const std::string& host, int port);
    bool bindAndListen(int port);
    bool acceptConnection();

private:
    SSL_CTX* ctx;
    SSL* ssl;
    int server_fd;
    std::string getServerPublicKey();
};
