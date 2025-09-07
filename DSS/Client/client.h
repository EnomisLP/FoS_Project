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
    bool authenticate(const std::string& username, const std::string& password);
    bool requestCreateKeys(const std::string& username, const std::string& password);
    void requestSignDoc(const std::string& username, const std::string& password, const std::string& path);
    std::string requestGetCertificate(const std::string& username);
    std::string requestDeleteCertificate(const std::string& username);
private:
    crypto& cryptoEngine;
};
