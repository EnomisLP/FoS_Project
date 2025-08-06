#pragma once
#include <string>
#include "Protocol/secureChannel.hpp"

class client {
public:
    client(const std::string& host, int port, const std::string& ca_cert_path);

    bool connectToServer();
    bool authenticate(const std::string& username, const std::string& password);

    bool requestCreateKeys();
    bool requestSignDoc(const std::string& document);
    std::string requestGetPublicKey(const std::string& username);
    bool requestDeleteKeys();

private:
    std::string host;
    int port;
    std::string ca_cert_path;
    secureChannel channel;
    std::string username;
};
