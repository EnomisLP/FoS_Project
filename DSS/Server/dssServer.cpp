#include "dssServer.hpp"
#include <iostream>

dssServer::dssServer(db& database, crypto& cryptoEngine)
    : database(database), cryptoEngine(cryptoEngine) {}

// Authenticate user by verifying username + password hash
bool dssServer::authenticate(const std::string& username, const std::string& password_hash) {
    return database.verifyUserPassword(username, password_hash);
}

// Create key pair for user if none exists
bool dssServer::handleCreateKeys(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "User not found: " << username << "\n";
        return false;
    }
    int user_id = *userIdOpt;

    // Check if keys already exist
    auto pubKeyOpt = database.getPublicKey(user_id);
    if (pubKeyOpt) {
        std::cout << "Key pair already exists for user: " << username << "\n";
        return false;
    }

    // Generate keys with password = username (or get password securely)
    auto keys = cryptoEngine.CreateKeys(username);

    if (keys.first.empty() || keys.second.empty()) {
        std::cerr << "Key generation failed.\n";
        return false;
    }

    // Store keys in DB (public and encrypted private)
    return database.storeKeys(user_id, keys.first, keys.second);
}

// Sign a document on behalf of user
std::optional<std::string> dssServer::handleSignDoc(const std::string& username, const std::string& document) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "User not found: " << username << "\n";
        return std::nullopt;
    }
    int user_id = *userIdOpt;

    // Get encrypted private key from DB
    auto encryptedPrivKeyOpt = database.getEncryptedPrivateKey(user_id);
    if (!encryptedPrivKeyOpt) {
        std::cerr << "No key pair found for user: " << username << "\n";
        return std::nullopt;
    }

    // Sign document using encrypted private key and username as password
    std::string signature = cryptoEngine.SignDoc(*encryptedPrivKeyOpt, username, document);
    if (signature.empty()) {
        std::cerr << "Signing document failed.\n";
        return std::nullopt;
    }

    return signature;
}

// Retrieve public key of a user
std::optional<std::string> dssServer::handleGetPublicKey(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "User not found: " << username << "\n";
        return std::nullopt;
    }
    int user_id = *userIdOpt;

    return database.getPublicKey(user_id);
}

// Delete user's key pair
bool dssServer::handleDeleteKeys(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "User not found: " << username << "\n";
        return false;
    }
    int user_id = *userIdOpt;

    bool dbDeleted = database.deleteKeys(user_id);
    bool cryptoDeleted = cryptoEngine.DeleteKeys(username);

    return dbDeleted && cryptoDeleted;
}
