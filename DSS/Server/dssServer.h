// dssServer.h
#pragma once
#include <string>
#include <unordered_map>
#include <optional>

#include "db.h"
#include "crypto.h"

class dssServer {
public:
    dssServer(db& database, crypto& cryptoEngine);

    std::string authenticate(const std::string& username, const std::string& password_hash);
    bool handleChangePassword(const std::string& username, const std::string& newPassword);
    bool handleCreateKeys(const std::string& username);
    std::optional<std::string> handleSignDoc(const std::string& username, const std::string& document);
    std::optional<std::string> handleGetPublicKey(const std::string& username);
    bool handleDeleteKeys(const std::string& username);
    std::string registerUser(const std::string& username, const std::string& tempPassword);
    bool authorizeAdmin(const std::string& username);
private:
    db& database;
    crypto& cryptoEngine;
};
