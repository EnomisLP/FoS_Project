#pragma once
#include "Protocol/secureChannelClient.h"
#include <string>

class client {
private:
    std::string username;
    std::string host;
    int port;

public:
    secureChannelClient channel;

    client(const std::string& host, int port);

    // Username accessors
    void setUsername(const std::string& uname) { username = uname; }
    std::string getUsername() const { return username; }

    // Channel setter
    void setChannel(const secureChannelClient& ch) { channel = ch; }

    bool authenticate(const std::string& username, const std::string& password);
    bool requestCreateKeys();
    bool requestSignDoc(const std::string& document);
    std::string requestGetPublicKey(const std::string& username);
    bool requestDeleteKeys();
};
