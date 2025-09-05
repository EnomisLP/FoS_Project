#include "dssServer.h"
#include "CA/CA.h"
#include "secureChannelCA.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>

dssServer::dssServer(db& database, crypto& cryptoEngine, const std::string& host, int port)
    : database(database), cryptoEngine(cryptoEngine), host(host), port(port) {}


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
bool dssServer::authorizeAdmin(const std::string& username) {
    // For now, just log the admin authorization
    std::cout << "[SERVER] Admin privileges granted to user: " << username << "\n";
    return true;
}


// Register new user with temporary password
std::string dssServer::registerUser(const std::string& username, const std::string& tempPassword) {
    if (database.userExists(username)) {
        return "USER_EXISTS";
    }
    if (!database.addUser(username, tempPassword, 0, 0)) {
        return "USER_REGISTRATION_FAILED";
    }

    std::cout << "[SERVER] New user registered: " << username 
              << " -- " << tempPassword << "\n";

    return "USER_REGISTERED";
}

// Authenticate user: normal or first login
std::string dssServer::authenticate(const std::string& username, const std::string& password_hash) {
    bool firstLogin = false;
    bool isAdmin = database.isAdmin(username);
    if (isAdmin) {
        std::cout << "[SERVER] User " << username << " is an admin.\n";
        authorizeAdmin(username);
        return "AUTH_ADMIN"; 
    }
    bool ok = database.verifyUserPasswordAndFirstLogin(username, password_hash, firstLogin);

    if (!ok) {
        return "AUTH_FAIL";
    }
    if (firstLogin) {
        std::cout << "[SERVER] First login detected for user: " << username << "\n";
        return "FIRST_LOGIN";
    } else {
        std::cout << "[SERVER] Normal login for user: " << username << "\n";
        return "AUTH_OK";
    }
}


// Create key pair for user if none exists
bool dssServer::handleCreateKeys(const std::string& username, const std::string& certPem) {
        auto userIdOpt = database.getUserId(username);
        if (!userIdOpt) {
            std::cerr << "[DSS] Unknown user: " << username << "\n";
            return false;
        }
        int userId = *userIdOpt;

        // Store certificate in DB
        if (!database.storeCertificate(userId, certPem)) {
            std::cerr << "[DSS] Failed to store certificate for " << username << "\n";
            return false;
        }

        std::cout << "[DSS] Certificate issued for user: " << username << "\n";
        return true;
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

// Get certificate
std::optional<std::string> dssServer::handleGetCertificate(const std::string& username) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) return std::nullopt;
    return database.getCertificate(username);
}

// Delete keys
bool dssServer::handleDeleteKeys(const std::string& username) {
  auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        return false; // user not found
    }
    int user_id = *userIdOpt;

    bool dbDeleted = database.deleteKeys(user_id);
    bool userDeleted = database.deleteUser(user_id);

    return dbDeleted && userDeleted;
}

