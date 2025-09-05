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
    bool verifyUserPassword(const std::string& username, const std::string& plainPassword);
    bool addUser(const std::string& username, const std::string& plainPassword, bool first_login, bool is_admin);
    bool userExists(const std::string& username);
    bool isFirstLogin(const std::string& username);
    bool isAdmin(const std::string& username);
    bool completeFirstLogin(const std::string& username);
    bool updateUserPassword(const std::string& username, const std::string& newPlainPassword, int firstLoginFlag);
    bool verifyUserPasswordAndFirstLogin(const std::string& username, const std::string& plainPassword, bool& firstLogin);
    bool deleteUser(int user_id);
    bool storePrivateKey(int user_id, const std::string& privKeyPem);
    std::optional<std::string> getCertificate(const std::string& username);
    // --- Key management ---
    bool storeCertificate(int user_id, const std::string& certPem);
    std::optional<std::string> getEncryptedPrivateKey(int user_id);
    bool deleteKeys(int user_id);

private:
    sqlite3* database;
};
