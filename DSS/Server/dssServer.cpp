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

std::string dssServer::requestCertificate(int userId, const std::string& csrPem) {
    // Send CSR to CA and get back signed certificate
    std::string request = "REQ_CERT " + std::to_string(userId) + " " + csrPem;
    channelCA.sendData(request);
    return channelCA.receiveData();
}


// Create key pair for user if none exists
bool dssServer::handleCreateKeys(const std::string& username, const std::string& password) {
    auto userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "[DSS] Unknown user: " << username << "\n";
        return false;
    }
    int userId = *userIdOpt;

    // 1) Generate keypair
    auto [privKeyPem, pubKeyPem] = cryptoEngine.generateKeypair();
    if (privKeyPem.empty() || pubKeyPem.empty()) {
        std::cerr << "[DSS] Failed to generate keypair for " << username << "\n";
        return false;
    }
    std::string encryptedPrivKey = cryptoEngine.encrypt_private_key(privKeyPem, password);
    if (encryptedPrivKey.empty()) {
        std::cerr << "[DSS] Failed to encrypt private key for " << username << "\n";
        return false;
    }
    // 2) Store private key securely (DSS DB or file)
    if (!database.storePrivateKey(userId, encryptedPrivKey)) {
        std::cerr << "[DSS] Failed to store private key for " << username << "\n";
        return false;
    }

    // 3) Generate CSR
    std::string csrPem = cryptoEngine.createCSR(username, pubKeyPem, privKeyPem);
    if (csrPem.empty()) {
        std::cerr << "[DSS] Failed to generate CSR for " << username << "\n";
        return false;
    }
    // Erase plaintext private key immediately
    std::fill(privKeyPem.begin(), privKeyPem.end(), 0);

    // 4) Send CSR to CA
    std::string certPem = requestCertificate(userId, csrPem);
    if (certPem.empty() || certPem == "ERROR") {
        std::cerr << "[DSS] CA failed to sign CSR for " << username << "\n";
        return false;
    }

    // 5) Store certificate in DSS DB
    if (!database.storeCertificate(userId, certPem)) {
        std::cerr << "[DSS] Failed to store certificate for " << username << "\n";
        return false;
    }

    std::cout << "[DSS] Certificate issued for user: " << username << "\n";

    return true;
}




// Sign document
std::optional<std::string> dssServer::handleSignDoc(const std::string& username, const std::string& password, const std::string& filePath) {
    std::optional<int> userIdOpt = database.getUserId(username);
    if (!userIdOpt) {
        std::cerr << "[DSS] User not found: " << username << "\n";
        return std::nullopt;
    }

    int userId = *userIdOpt;

    std::optional<std::string> encryptedPrivKeyOpt = database.getEncryptedPrivateKey(userId);
    if (!encryptedPrivKeyOpt) {
        std::cerr << "[DSS] No encrypted private key found for user: " << username << "\n";
        return std::nullopt;
    }
    std::string encryptedPrivKey = *encryptedPrivKeyOpt;
    // Decrypt the private key
    std::string privKeyPem = cryptoEngine.decrypt_private_key(encryptedPrivKey, password);

    // Sign the file
    std::string signature = cryptoEngine.signFile(privKeyPem, filePath);

    // Clear decrypted key from memory
    std::fill(privKeyPem.begin(), privKeyPem.end(), 0);

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
        std::cerr << "[DSS] User not found: " << username << "\n";
        return false;
    }
    int userId = *userIdOpt;

    // Get user's certificate to revoke at CA
    auto certPemOpt = database.getCertificate(username);
    if (certPemOpt) {
        std::string request = "REVOKE_CERT " + std::to_string(userId) + " " + *certPemOpt;
        channelCA.sendData(request);
        std::string caResponse = channelCA.receiveData();
        if (caResponse != "REVOKE_OK") {
            std::cerr << "[DSS] CA failed to revoke certificate for user " << username << "\n";
            return false;
        }
        std::cout << "[DSS] Certificate revoked at CA for user " << username << "\n";
    }

    // Delete keys from DSS DB
    bool dbDeleted = database.deleteKeys(userId);
    bool userDeleted = database.deleteUser(userId);

    return dbDeleted && userDeleted;
}


