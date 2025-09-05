#pragma once
#include "Protocol/secureChannelClient.h"
#include "Server/crypto.h"
#include <string>

class client {
private:
    std::string username;
    std::string host;
    int port;

public:
    secureChannelClient channel;

    client(const std::string& host, int port, crypto& cryptoEngine);

    // Username accessors
    void setUsername(const std::string& uname) { username = uname; }
    std::string getUsername() const { return username; }

    // Channel setter
    void setChannel(const secureChannelClient& ch) { channel = ch; }
    std::string requestCertificate(const std::string& csrPem);
    bool authenticate(const std::string& username, const std::string& password);
    bool requestCreateCertificate(const std::string& username);
    bool requestSignDoc(const std::string& document);
    std::string requestGetCertificate(const std::string& username);
    void requestDeleteCertificate(const std::string& username);
private:
    crypto& cryptoEngine;
};
