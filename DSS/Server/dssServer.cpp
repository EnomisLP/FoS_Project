#include "dssServer.h"
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

dssServer::dssServer(db& database, crypto& cryptoEngine)
    : database(database), cryptoEngine(cryptoEngine) 
{
    // Load offline users from JSON into a map
    std::ifstream inFile("Projects/FoS_Project/DSS/DB/offline_users.json");
    if (inFile.is_open()) {
        nlohmann::json offlineJson;
        inFile >> offlineJson;
        inFile.close();

        for (auto& [username, info] : offlineJson.items()) {
            offlineUsers[username] = {
                info["temp_password"].get<std::string>(),
                info["server_pubkey"].get<std::string>()
            };
        }
    }
}

// Authenticate user: normal or first login
bool dssServer::authenticate(const std::string& username, const std::string& password_hash) {
    // First check if user is in offline registrations
    auto it = offlineUsers.find(username);
    if (it != offlineUsers.end()) {
        // For first login, password_hash should match temp password
        if (password_hash == it->second.tempPassword) {
            std::cout << "[Server] First login detected for user: " << username << "\n";
            return true;
        }
        return false;
    }

    // Otherwise check regular DB
    return database.verifyUserPassword(username, password_hash);
}

// Handle password change for first login
bool dssServer::handleChangePassword(const std::string& username, const std::string& newPassword) {
    auto it = offlineUsers.find(username);
    if (it == offlineUsers.end()) {
        std::cerr << "[Server] No offline registration found for user: " << username << "\n";
        return false;
    }

    // Add user to the DB with new password and first_login = 0
    if (!database.addUser(username, newPassword, /*first_login=*/0)) {
        std::cerr << "[Server] Failed to add user to DB: " << username << "\n";
        return false;
    }

    std::cout << "[Server] Password changed and user added to DB: " << username << "\n";
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

    bool dbDeleted = database.deleteKeys(user_id);
    bool cryptoDeleted = cryptoEngine.DeleteKeys(username);

    return dbDeleted && cryptoDeleted;
}
