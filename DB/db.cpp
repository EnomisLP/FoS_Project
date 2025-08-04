// db.cpp
#include "DB/db.hpp"
#include <iostream>

db::db(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &database) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(database) << "\n";
        database = nullptr;
    }
}

db::~db() {
    if (database) sqlite3_close(database);
}

bool db::init() {
    const char* users_sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_login BOOLEAN DEFAULT 1
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
        std::cerr << "Error creating users table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    if (sqlite3_exec(database, keys_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "Error creating keys table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

std::optional<int> db::getUserId(const std::string& username) {
    const char* sql = "SELECT id FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return id;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool db::verifyUserPassword(const std::string& username, const std::string& password_hash) {
    const char* sql = R"(
        SELECT 1 FROM users WHERE username = ? AND password_hash = ?
    )";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);

    bool valid = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return valid;
}

bool db::setPasswordHash(const std::string& username, const std::string& new_password_hash) {
    const char* sql = R"(
        UPDATE users SET password_hash = ?, first_login = 0 WHERE username = ?
    )";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, new_password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db::isFirstLogin(const std::string& username) {
    const char* sql = "SELECT first_login FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
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
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool db::storeKeys(int user_id, const std::string& pubKey, const std::string& encryptedPrivKey) {
    const char* sql = R"(
        INSERT OR REPLACE INTO keys (user_id, public_key, encrypted_private_key)
        VALUES (?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, pubKey.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedPrivKey.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<std::string> db::getEncryptedPrivateKey(int user_id) {
    const char* sql = "SELECT encrypted_private_key FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, user_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return result;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::optional<std::string> db::getPublicKey(int user_id) {
    const char* sql = "SELECT public_key FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, user_id);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string result = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return result;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool db::deleteKeys(int user_id) {
    const char* sql = "DELETE FROM keys WHERE user_id = ?";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, user_id);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}
