#pragma once
#include <string>
#include "crypto.hpp"
#include "Models/models.hpp"
#include "DB/db.hpp"
class dssServer {
public:
    dssServer(db& database, crypto& cryptoEngine);

    // Auth
    bool authenticate(const std::string& username, const std::string& password_hash);

    // Operations
    bool handleCreateKeys(const std::string& username);
    std::optional<std::string> handleSignDoc(const std::string& username, const std::string& document);
    std::optional<std::string> handleGetPublicKey(const std::string& username);
    bool handleDeleteKeys(const std::string& username);

private:
    db& database;
    crypto& cryptoEngine;
};
