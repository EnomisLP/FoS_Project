#include "dssServer.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

dssServer::dssServer(db& database, crypto& cryptoEngine)
    : database(database), cryptoEngine(cryptoEngine) {}


// Handle password change for first login
bool dssServer::handleChangePassword(const std::string& username, const std::string& newPassword) {
    // Just update directly in DB
    if (!database.updateUserPassword(username, newPassword, 1)) {
        std::cerr << "[SERVER] Failed to update password for DB user: " << username << "\n";
        return false;
    }

    std::cout << "[SERVER] Password changed for DB user: " << username << "\n";
    return true;
}



// Authenticate user: normal or first login
bool dssServer::authenticate(const std::string& username, const std::string& password_hash) {
    bool firstLogin = false;
    bool ok = database.verifyUserPasswordAndFirstLogin(username, password_hash, firstLogin);

    if (!ok) {
        return false;
    }

    if (firstLogin) {
        std::cout << "[SERVER] First login detected for user: " << username << "\n";
    } else {
        std::cout << "[SERVER] Normal login for user: " << username << "\n";
    }

    return true;
}




// Create key pair for user if none exists
bool dssServer::handleCreateKeys(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "User not found: " << username << "\n";
        return false;
    }
    int user_id = *userIdOpt;

    auto pubKeyOpt = database.getPublicKey(user_id);
    if (pubKeyOpt) {
        std::cout << "Key pair already exists for user: " << username << "\n";
        return false;
    }

    auto keys = cryptoEngine.CreateKeys(username);
    if (keys.first.empty() || keys.second.empty()) {
        std::cerr << "Key generation failed.\n";
        return false;
    }

    return database.storeKeys(user_id, keys.first, keys.second);
}

// Sign document
std::optional<std::string> dssServer::handleSignDoc(const std::string& username, const std::string& document) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) return std::nullopt;
    int user_id = *userIdOpt;

    auto encryptedPrivKeyOpt = database.getEncryptedPrivateKey(user_id);
    if (!encryptedPrivKeyOpt) return std::nullopt;

    std::string signature = cryptoEngine.SignDoc(*encryptedPrivKeyOpt, username, document);
    if (signature.empty()) return std::nullopt;

    return signature;
}

// Get public key
std::optional<std::string> dssServer::handleGetPublicKey(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) return std::nullopt;
    return database.getPublicKey(*userIdOpt);
}

// Delete keys
bool dssServer::handleDeleteKeys(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) return false;
    int user_id = *userIdOpt;

    // Delete keys first
    bool dbDeleted = database.deleteKeys(user_id);
    // Delete the user from the database
    bool userDeleted = database.deleteUser(user_id);

    return dbDeleted && userDeleted;
}

