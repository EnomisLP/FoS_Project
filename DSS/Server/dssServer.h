// dssServer.h
#pragma once
#include <string>
#include <unordered_map>
#include <optional>
#include "Protocol/secureChannelClient.h"
#include "db.h"
#include "crypto.h"

class dssServer {
    private:
    std::string host;
    int port;
public:
    
    dssServer(db& database, crypto& cryptoEngine, secureChannelClient& channelCA);

    std::string authenticate(const std::string& username, const std::string& password_hash);
    bool handleChangePassword(const std::string& username, const std::string& newPassword);
    bool handleCreateKeys(const std::string& username, const std::string& password);
    bool handleSignDoc(const std::string& username, const std::string& password, const std::string& document);
    std::optional<std::string> handleGetCertificate(const std::string& username);
    std::string requestCertificate(int userId, const std::string& csrPem);
    bool handleDeleteKeys(const std::string& username);
    std::string registerUser(const std::string& username, const std::string& tempPassword);
    
private:
    db& database;
    crypto& cryptoEngine;
    secureChannelClient& channelCA;
};
