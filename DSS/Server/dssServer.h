#pragma once
#include "DB/db.h"
#include "crypto.h"
#include <string>
class dssServer {
public:
    dssServer(db& database, crypto& cryptoEngine);

    // Auth
    bool authenticate(const std::string& username, const std::string& password_hash);
    bool handleChangePassword(const std::string& username, const std::string& newPassword);
    // Operations
    bool handleCreateKeys(const std::string& username);
    std::optional<std::string> handleSignDoc(const std::string& username, const std::string& document);
    std::optional<std::string> handleGetPublicKey(const std::string& username);
    bool handleDeleteKeys(const std::string& username);

private:
    db& database;
    crypto& cryptoEngine;
};
