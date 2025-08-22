#pragma once
#include <string>
#include <optional>
#include <sqlite3.h>

class db {
private:
    sqlite3* database;

public:
    db(const std::string& db_path);
    ~db();

    // Check if DB successfully opened
    bool isOpen() const;

    // Initialize tables
    bool init();

    // User operations
    std::optional<int> getUserId(const std::string& username);
    bool verifyUserPassword(const std::string& username, const std::string& password_hash);
    bool setPasswordHash(const std::string& username, const std::string& new_password_hash);
    bool isFirstLogin(const std::string& username);
    bool completeFirstLogin(const std::string& username);

    // Key operations
    bool storeKeys(int user_id, const std::string& pubKey, const std::string& encryptedPrivKey);
    std::optional<std::string> getEncryptedPrivateKey(int user_id);
    std::optional<std::string> getPublicKey(int user_id);
    bool deleteKeys(int user_id);

    // Get raw SQLite pointer
    sqlite3* getRawDB() const { return database; }
};
