#include "db.h"
#include <Server/crypto.h>
#include <iostream>
#include <filesystem>
#include <chrono>


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
        cert_pem TEXT,
        private_key TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    )";

    // Separate nonce tables for client and DSS
    const char* client_nonces_sql = R"(
        CREATE TABLE IF NOT EXISTS client_nonces (
        owner TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expiry INTEGER NOT NULL,
        PRIMARY KEY (owner, nonce)
        );
    )";

    const char* dss_nonces_sql = R"(
        CREATE TABLE IF NOT EXISTS dss_nonces (
        owner TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expiry INTEGER NOT NULL,
        PRIMARY KEY (owner, nonce)
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

    if (sqlite3_exec(database, client_nonces_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[DB] Error creating client_nonces table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    if (sqlite3_exec(database, dss_nonces_sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[DB] Error creating dss_nonces table: " << errMsg << "\n";
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}

// Client nonce functions
bool db::storeClientNonceIfFresh(const std::string& owner, const std::string& nonce, int ttl_seconds) {
    if (!database) {
        std::cerr << "[DB] Database not initialized\n";
        return false;
    }
    if (owner.empty() || nonce.empty()) {
        std::cerr << "[DB] Empty owner or nonce\n";
        return false;
    }

    std::time_t now = std::time(nullptr);
    
    // 1) Remove expired entries
    const char* cleanup_sql = "DELETE FROM client_nonces WHERE expiry <= ?;";
    sqlite3_stmt* cleanupStmt = nullptr;
    if (sqlite3_prepare_v2(database, cleanup_sql, -1, &cleanupStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(cleanupStmt, 1, static_cast<sqlite3_int64>(now));
        sqlite3_step(cleanupStmt);
        int changes = sqlite3_changes(database);
        
    }
    if (cleanupStmt) sqlite3_finalize(cleanupStmt);

    // Check if nonce already exists (for debugging)
    const char* check_sql = "SELECT expiry FROM client_nonces WHERE owner = ? AND nonce = ?;";
    sqlite3_stmt* checkStmt = nullptr;
    if (sqlite3_prepare_v2(database, check_sql, -1, &checkStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(checkStmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(checkStmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(checkStmt) == SQLITE_ROW) {
            sqlite3_int64 existing_expiry = sqlite3_column_int64(checkStmt, 0);
            std::cout << "[DB] Client nonce already exists! Expiry: " << existing_expiry 
                      << ", Current time: " << now << ", Expired: " << (existing_expiry <= now ? "YES" : "NO") << "\n";
        } else {
            std::cout << "[DB] Client nonce does not exist yet\n";
        }
    }
    if (checkStmt) sqlite3_finalize(checkStmt);

    // 2) Try insert (will fail with UNIQUE constraint if already exists)
    const char* insert_sql = "INSERT INTO client_nonces(owner, nonce, expiry) VALUES(?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB] prepare storeClientNonceIfFresh failed: " << sqlite3_errmsg(database) << "\n";
        return false;
    }

    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_int64 expiry_time = static_cast<sqlite3_int64>(now + ttl_seconds);
    sqlite3_bind_int64(stmt, 3, expiry_time);

    

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        std::cout << "[DB] Client nonce inserted successfully\n";
        return true;
    } else if (rc == SQLITE_CONSTRAINT) {
        std::cout << "[DB] Client nonce insertion failed - CONSTRAINT violation (replay detected)\n";
        return false;
    } else {
        std::cerr << "[DB] storeClientNonceIfFresh unexpected rc: " << rc << " - " << sqlite3_errmsg(database) << "\n";
        return false;
    }
}

// DSS nonce functions
bool db::storeDSSNonceIfFresh(const std::string& owner, const std::string& nonce, int ttl_seconds) {
    if (!database) {
        std::cerr << "[DB] Database not initialized\n";
        return false;
    }
    if (owner.empty() || nonce.empty()) {
        std::cerr << "[DB] Empty owner or nonce\n";
        return false;
    }

    std::time_t now = std::time(nullptr);
    

    // 1) Remove expired entries
    const char* cleanup_sql = "DELETE FROM dss_nonces WHERE expiry <= ?;";
    sqlite3_stmt* cleanupStmt = nullptr;
    if (sqlite3_prepare_v2(database, cleanup_sql, -1, &cleanupStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(cleanupStmt, 1, static_cast<sqlite3_int64>(now));
        sqlite3_step(cleanupStmt);
        int changes = sqlite3_changes(database);
    }
    if (cleanupStmt) sqlite3_finalize(cleanupStmt);

    // Check if nonce already exists (for debugging)
    const char* check_sql = "SELECT expiry FROM dss_nonces WHERE owner = ? AND nonce = ?;";
    sqlite3_stmt* checkStmt = nullptr;
    if (sqlite3_prepare_v2(database, check_sql, -1, &checkStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(checkStmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(checkStmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(checkStmt) == SQLITE_ROW) {
            sqlite3_int64 existing_expiry = sqlite3_column_int64(checkStmt, 0);
            std::cout << "[DB] DSS nonce already exists! Expiry: " << existing_expiry 
                      << ", Current time: " << now << ", Expired: " << (existing_expiry <= now ? "YES" : "NO") << "\n";
        } else {
            std::cout << "[DB] DSS nonce does not exist yet\n";
        }
    }
    if (checkStmt) sqlite3_finalize(checkStmt);

    // 2) Try insert (will fail with UNIQUE constraint if already exists)
    const char* insert_sql = "INSERT INTO dss_nonces(owner, nonce, expiry) VALUES(?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB] prepare storeDSSNonceIfFresh failed: " << sqlite3_errmsg(database) << "\n";
        return false;
    }

    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_int64 expiry_time = static_cast<sqlite3_int64>(now + ttl_seconds);
    sqlite3_bind_int64(stmt, 3, expiry_time);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        std::cout << "[DB] DSS nonce inserted successfully\n";
        return true;
    } else if (rc == SQLITE_CONSTRAINT) {
        std::cout << "[DB] DSS nonce insertion failed - CONSTRAINT violation (replay detected)\n";
        return false;
    } else {
        std::cerr << "[DB] storeDSSNonceIfFresh unexpected rc: " << rc << " - " << sqlite3_errmsg(database) << "\n";
        return false;
    }
}

bool db::isClientNoncePresent(const std::string& owner, const std::string& nonce) {
    if (!database) return false;
    const char* sql = "SELECT expiry FROM client_nonces WHERE owner = ? AND nonce = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    std::time_t now = std::time(nullptr);
    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);

    bool present = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 0);
        present = (expiry > now);
        std::cout << "[DB] isClientNoncePresent - owner: " << owner << ", Nonce: " << nonce 
                  << ", Expiry: " << expiry << ", Now: " << now 
                  << ", Present: " << (present ? "YES" : "NO") << "\n";
    }
    sqlite3_finalize(stmt);
    return present;
}

bool db::isDSSNoncePresent(const std::string& owner, const std::string& nonce) {
    if (!database) return false;
    const char* sql = "SELECT expiry FROM dss_nonces WHERE owner = ? AND nonce = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    std::time_t now = std::time(nullptr);
    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);

    bool present = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 0);
        present = (expiry > now);
        std::cout << "[DB] isDSSNoncePresent - owner : " << owner << ", Nonce: " << nonce 
                  << ", Expiry: " << expiry << ", Now: " << now 
                  << ", Present: " << (present ? "YES" : "NO") << "\n";
    }
    sqlite3_finalize(stmt);
    return present;
}

void db::cleanupExpiredClientNonces() {
    if (!database) return;
    std::time_t now = std::time(nullptr);
    std::cout << "[DB] cleanupExpiredClientNonces - Current time: " << now << "\n";
    
    const char* sql = "DELETE FROM client_nonces WHERE expiry <= ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));
    sqlite3_step(stmt);
    int changes = sqlite3_changes(database);
    std::cout << "[DB] Cleaned up " << changes << " expired client nonces\n";
    sqlite3_finalize(stmt);
}

void db::cleanupExpiredDSSNonces() {
    if (!database) return;
    std::time_t now = std::time(nullptr);
    std::cout << "[DB] cleanupExpiredDSSNonces - Current time: " << now << "\n";
    
    const char* sql = "DELETE FROM dss_nonces WHERE expiry <= ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));
    sqlite3_step(stmt);
    int changes = sqlite3_changes(database);
    std::cout << "[DB] Cleaned up " << changes << " expired DSS nonces\n";
    sqlite3_finalize(stmt);
}

// Clear all nonces for testing
void db::clearAllClientNonces() {
    if (!database) return;
    const char* sql = "DELETE FROM client_nonces;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_step(stmt);
        int changes = sqlite3_changes(database);
        std::cout << "[DB] Cleared " << changes << " client nonces from database\n";
    }
    if (stmt) sqlite3_finalize(stmt);
}

void db::clearAllDSSNonces() {
    if (!database) return;
    const char* sql = "DELETE FROM dss_nonces;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_step(stmt);
        int changes = sqlite3_changes(database);
        std::cout << "[DB] Cleared " << changes << " DSS nonces from database\n";
    }
    if (stmt) sqlite3_finalize(stmt);
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
    std::cout << "[DEBUG] Checking hash: " << password_hash << std::endl;

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


bool db::storePrivateKey(int user_id, const std::string& private_key) {
    const char* sql =
        "INSERT INTO keys (user_id, private_key) VALUES (?, ?) "
        "ON CONFLICT(user_id) DO UPDATE "
        "SET private_key = excluded.private_key, created_at = CURRENT_TIMESTAMP";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB] Failed to prepare statement: " << sqlite3_errmsg(database) << "\n";
        return false;
    }

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, private_key.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[DB] Failed to execute storePrivateKey: " << sqlite3_errmsg(database) << "\n";
    }

    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
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
bool db::storeCertificate(int user_id, const std::string& certPem) {
    const char* sql = "INSERT INTO keys (user_id, cert_pem) VALUES (?, ?)"
                      "ON CONFLICT(user_id) DO UPDATE SET cert_pem = excluded.cert_pem, created_at = CURRENT_TIMESTAMP";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(database, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, certPem.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<std::string> db::getEncryptedPrivateKey(int user_id) {
    const char* sql = "SELECT private_key FROM keys WHERE user_id = ?";
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

std::optional<std::string> db::getCertificate(int user_id) {
    const char* sql = "SELECT cert_pem FROM keys WHERE user_id = ?";
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
