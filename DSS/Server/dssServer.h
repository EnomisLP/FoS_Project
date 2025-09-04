// dssServer.h
#pragma once
#include <string>
#include <unordered_map>
#include <optional>
#include "Protocol/secureChannelCA.h"
#include "db.h"
#include "crypto.h"

class dssServer {
    private:
    std::string host;
    int port;
public:
    secureChannelCA channelCA;
    dssServer(db& database, crypto& cryptoEngine, const std::string& host, int port);

    std::string authenticate(const std::string& username, const std::string& password_hash);
    bool handleChangePassword(const std::string& username, const std::string& newPassword);
    bool handleCreateKeys(const std::string& username, const std::string& serial);
    std::optional<std::string> handleSignDoc(const std::string& username, const std::string& document);
    std::optional<std::string> handleGetPublicKey(const std::string& username);
    bool handleDeleteKeys(const std::string& username);
    std::string registerUser(const std::string& username, const std::string& tempPassword);
    bool authorizeAdmin(const std::string& username);
private:
    db& database;
    crypto& cryptoEngine;
};
