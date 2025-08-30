#include "db.h"
#include <Server/crypto.h>
#include <iostream>
#include <filesystem>


db::db(const std::string& db_path) : database(nullptr) {
    std::cout << "[DB] Attempting to open: " << db_path << std::endl;
    if (sqlite3_open(db_path.c_str(), &database) != SQLITE_OK) {
        std::cerr << "[DB] Failed to open database: " << sqlite3_errmsg(database) << "\n";
        database = nullptr;
    } else {
        std::cout << "[DB] Opened: " << sqlite3_db_filename(database, "main") << std::endl;
    }
}

db::~db() {
    if (database) sqlite3_close(database);
}

bool db::isOpen() const {
    return database != nullptr;
}

bool db::init() {
    if (!database) return false;

    const char* users_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_login BOOLEAN DEFAULT 0,
            is_admin BOOLEAN DEFAULT 0
        );
    )";

    const char* keys_sql = R"(
        CREATE TABLE IF NOT EXISTS keys (
            user_id INTEGER PRIMARY KEY,
            public_key TEXT NOT NULL,
            encrypted_private_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    char* errMsg = nullptr;
    if (sqlite3_exec(database, users_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[DB] Error creating users table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    if (sqlite3_exec(database, keys_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[DB] Error creating keys table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

std::optional<int> db::getUserId(const std::string& username) {
    const char* sql = "SELECT id FROM users WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) 
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<int> userIdOpt = std::nullopt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        userIdOpt = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return userIdOpt;
}
bool db::verifyUserPassword(const std::string& username, const std::string& plainPassword) {
    std::string password_hash = crypto::hash_password(plainPassword);

    const char* sql = "SELECT 1 FROM users WHERE username = ? AND password_hash = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);

    bool valid = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    std::cout << "[DB] User " << username << (valid ? " is valid." : " is invalid.") << std::endl;
    return valid;
}

bool db::updateUserPassword(const std::string& username, const std::string& newPlainPassword, int firstLoginFlag) {
    std::string password_hash = crypto::hash_password(newPlainPassword);

    const char* sql = "UPDATE users SET password_hash = ?, first_login = ? WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, firstLoginFlag);
    sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_TRANSIENT);

    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return success;
}

bool db::addUser(const std::string& username, const std::string& plainPassword, bool first_login, bool is_admin) {
    std::string password_hash = crypto::hash_password(plainPassword);

    const char* sql = "INSERT INTO users (username, password_hash, first_login, is_admin) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, first_login ? 1 : 0);
    sqlite3_bind_int(stmt, 4, is_admin ? 1 : 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db::verifyUserPasswordAndFirstLogin(const std::string& username,
                                         const std::string& plainPassword,
                                         bool& firstLogin) {
    std::string password_hash = crypto::hash_password(plainPassword);

    const char* sql = "SELECT first_login FROM users WHERE username = ? AND password_hash = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);

    bool valid = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        valid = true;
        firstLogin = (sqlite3_column_int(stmt, 0) == 0); // 0 = first login, 1 = already changed
    }

    sqlite3_finalize(stmt);

    std::cout << "[DB] User " << username
              << (valid ? " is valid. First login = " + std::to_string(firstLogin) : " is invalid.")
              << std::endl;

    return valid;
}


bool db::isFirstLogin(const std::string& username) {
    const char* sql = "SELECT first_login FROM users WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool result = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) != 0;
    }

    sqlite3_finalize(stmt);
    return result;
}
bool db::userExists(const std::string& username) {
    const char* sql = "SELECT 1 FROM users WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool result = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) != 0;
    }

    sqlite3_finalize(stmt);
    return result;
}

bool db::isAdmin(const std::string& username) {
    const char* sql = "SELECT is_admin FROM users WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool result = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) != 0;
    }

    sqlite3_finalize(stmt);
    return result;
}

bool db::completeFirstLogin(const std::string& username) {
    const char* sql = "UPDATE users SET first_login = 0 WHERE username = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// --- Key functions ---
bool db::storeKeys(int user_id, const std::string& pubKey, const std::string& encryptedPrivKey) {
    const char* sql = R"(
        INSERT OR REPLACE INTO keys (user_id, public_key, encrypted_private_key, created_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP);
    )";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, pubKey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedPrivKey.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<std::string> db::getEncryptedPrivateKey(int user_id) {
    const char* sql = "SELECT encrypted_private_key FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;

    sqlite3_bind_int(stmt, 1, user_id);

    std::optional<std::string> result = std::nullopt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    return result;
}

std::optional<std::string> db::getPublicKey(int user_id) {
    const char* sql = "SELECT public_key FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;

    sqlite3_bind_int(stmt, 1, user_id);

    std::optional<std::string> result = std::nullopt;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    }

    sqlite3_finalize(stmt);
    return result;
}

bool db::deleteKeys(int user_id) {
    const char* sql = "DELETE FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
bool db::deleteUser(int user_id) {
    const char* sql = "DELETE FROM users WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, user_id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

