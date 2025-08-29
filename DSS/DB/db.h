#pragma once
#include <string>
#include <optional>
#include <sqlite3.h>

class db {
public:
    explicit db(const std::string& db_path);
    ~db();

    bool isOpen() const;
    bool init();

    // --- User management ---
    std::optional<int> getUserId(const std::string& username);
    bool verifyUserPassword(const std::string& username, const std::string& password_hash);
    bool addUser(const std::string& username, const std::string& password_hash, bool first_login, bool is_admin);
    bool userExists(const std::string& username);
    bool setPasswordHash(const std::string& username, const std::string& new_password_hash);
    bool isFirstLogin(const std::string& username);
    bool isAdmin(const std::string& username);
    bool completeFirstLogin(const std::string& username);
    bool updateUserPassword(const std::string& username, const std::string& newPassword, int firstLoginFlag);
    bool verifyUserPasswordAndFirstLogin(const std::string& username, const std::string& password_hash, bool& firstLogin);
    bool deleteUser(int user_id);
    // --- Key management ---
    bool storeKeys(int user_id, const std::string& pubKey, const std::string& encryptedPrivKey);
    std::optional<std::string> getEncryptedPrivateKey(int user_id);
    std::optional<std::string> getPublicKey(int user_id);
    bool deleteKeys(int user_id);

private:
    sqlite3* database;
};
