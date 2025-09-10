#include "dbCA.h"
#include <iostream>
#include <sstream>
#include <ctime>
#include <chrono>

dbCA::dbCA(const std::string& path) : dbPath(path), db(nullptr) {
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "[dbCA] Failed to open DB: " << sqlite3_errmsg(db) << "\n";
        db = nullptr;
    }
}

dbCA::~dbCA() {
    if (db) sqlite3_close(db);
}

bool dbCA::initDB() {
    const std::string sql = R"(
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cert_pem TEXT NOT NULL,
            serial_number TEXT UNIQUE NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            status TEXT NOT NULL,
            revoked_at TEXT
        );
    )";
    const char* nonces_sql = R"(
        CREATE TABLE IF NOT EXISTS nonces (
        owner   TEXT NOT NULL,
        nonce   TEXT NOT NULL,
        expiry  INTEGER NOT NULL,
        PRIMARY KEY (owner, nonce)
        );
    )";
    return execute(sql) && execute(nonces_sql);
}

bool dbCA::execute(const std::string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "[dbCA] SQL error: " << (errMsg ? errMsg : "unknown") << "\n";
        if (errMsg) sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool dbCA::storeCertificate(int user_id,
                            const std::string& cert_pem,
                            const std::string& serial_number,
                            const std::string& issued_at,
                            const std::string& expires_at) {
    std::string sql = "INSERT INTO certificates "
                      "(user_id, cert_pem, serial_number, issued_at, expires_at, status) "
                      "VALUES (?, ?, ?, ?, ?, 'valid');";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return false;
    
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, cert_pem.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, serial_number.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, issued_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, expires_at.c_str(), -1, SQLITE_TRANSIENT);

    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

bool dbCA::storeNonceIfFresh(const std::string& owner, const std::string& nonce, int ttl_seconds) {
    if (!db) {
        std::cerr << "[DB] Database not initialized\n";
        return false;
    }
    if (owner.empty() || nonce.empty()) {
        std::cerr << "[DB] Empty owner or nonce\n";
        return false;
    }

    std::time_t now = std::time(nullptr);
    std::cout << "[DB] storeNonceIfFresh - Owner: " << owner << ", Nonce: " << nonce 
              << ", TTL: " << ttl_seconds << ", Now: " << now << "\n";

    // 1) remove expired entries
    const char* cleanup_sql = "DELETE FROM nonces WHERE expiry <= ?;";
    sqlite3_stmt* cleanupStmt = nullptr;
    if (sqlite3_prepare_v2(db, cleanup_sql, -1, &cleanupStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(cleanupStmt, 1, static_cast<sqlite3_int64>(now));
        int cleanup_result = sqlite3_step(cleanupStmt);
        int changes = sqlite3_changes(db);
        std::cout << "[DB] Cleanup: removed " << changes << " expired nonces\n";
    }
    if (cleanupStmt) sqlite3_finalize(cleanupStmt);

    // Check if nonce already exists (for debugging)
    const char* check_sql = "SELECT expiry FROM nonces WHERE owner = ? AND nonce = ?;";
    sqlite3_stmt* checkStmt = nullptr;
    if (sqlite3_prepare_v2(db, check_sql, -1, &checkStmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(checkStmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(checkStmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(checkStmt) == SQLITE_ROW) {
            sqlite3_int64 existing_expiry = sqlite3_column_int64(checkStmt, 0);
            std::cout << "[DB] Nonce already exists! Expiry: " << existing_expiry 
                      << ", Current time: " << now << ", Expired: " << (existing_expiry <= now ? "YES" : "NO") << "\n";
        } else {
            std::cout << "[DB] Nonce does not exist yet\n";
        }
    }
    if (checkStmt) sqlite3_finalize(checkStmt);

    // 2) try insert (will fail with UNIQUE constraint if already exists)
    const char* insert_sql = "INSERT INTO nonces(owner, nonce, expiry) VALUES(?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[DB] prepare storeNonceIfFresh failed: " << sqlite3_errmsg(db) << "\n";
        return false;
    }

    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_int64 expiry_time = static_cast<sqlite3_int64>(now + ttl_seconds);
    sqlite3_bind_int64(stmt, 3, expiry_time);

    std::cout << "[DB] Attempting to insert nonce with expiry: " << expiry_time << "\n";

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        std::cout << "[DB] Nonce inserted successfully\n";
        return true;
    } else if (rc == SQLITE_CONSTRAINT) {
        std::cout << "[DB] Nonce insertion failed - CONSTRAINT violation (replay detected)\n";
        return false;
    } else {
        std::cerr << "[DB] storeNonceIfFresh unexpected rc: " << rc << " - " << sqlite3_errmsg(db) << "\n";
        return false;
    }
}

bool dbCA::isNoncePresent(const std::string& owner, const std::string& nonce) {
    if (!db) return false;
    const char* sql = "SELECT expiry FROM nonces WHERE owner = ? AND nonce = ? LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    std::time_t now = std::time(nullptr);
    sqlite3_bind_text(stmt, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, nonce.c_str(), -1, SQLITE_TRANSIENT);

    bool present = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_int64 expiry = sqlite3_column_int64(stmt, 0);
        present = (expiry > now);
        std::cout << "[DB] isNoncePresent - Owner: " << owner << ", Nonce: " << nonce 
                  << ", Expiry: " << expiry << ", Now: " << now 
                  << ", Present: " << (present ? "YES" : "NO") << "\n";
    }
    sqlite3_finalize(stmt);
    return present;
}

void dbCA::cleanupExpiredNonces() {
    if (!db) return;
    std::time_t now = std::time(nullptr);
    std::cout << "[DB] cleanupExpiredNonces - Current time: " << now << "\n";
    
    const char* sql = "DELETE FROM nonces WHERE expiry <= ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(now));
    sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    std::cout << "[DB] Cleaned up " << changes << " expired nonces\n";
    sqlite3_finalize(stmt);
}

// Add this method to manually clear all nonces for testing
void dbCA::clearAllNonces() {
    if (!db) return;
    const char* sql = "DELETE FROM nonces;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_step(stmt);
        int changes = sqlite3_changes(db);
        std::cout << "[DB] Cleared " << changes << " nonces from database\n";
    }
    if (stmt) sqlite3_finalize(stmt);
}
std::optional<CertificateRecord> dbCA::getCertificate(const std::string& serial_number) {
    std::string sql = "SELECT * FROM certificates WHERE serial_number=?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;

    sqlite3_bind_text(stmt, 1, serial_number.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<CertificateRecord> record;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        record = CertificateRecord{
            sqlite3_column_int(stmt, 0),
            sqlite3_column_int(stmt, 1),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)),
            sqlite3_column_text(stmt, 7) ? std::optional<std::string>{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))} : std::nullopt
        };
    }

    sqlite3_finalize(stmt);
    return record;
}

std::vector<CertificateRecord> dbCA::getAllCertificates() {
    std::vector<CertificateRecord> results;
    std::string sql = "SELECT * FROM certificates;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(CertificateRecord{
            sqlite3_column_int(stmt, 0),
            sqlite3_column_int(stmt, 1),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)),
            sqlite3_column_text(stmt, 7) ? std::optional<std::string>{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))} : std::nullopt
        });
    }

    sqlite3_finalize(stmt);
    return results;
}

std::string dbCA::getCertPemByUser(int userId) {
    const char* sql = "SELECT cert_pem FROM certificates WHERE user_id=? LIMIT 1;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_int(stmt, 1, userId);

    std::string certPem;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text) {
            certPem = reinterpret_cast<const char*>(text);
        }
    }

    sqlite3_finalize(stmt);
    return certPem;
}
bool dbCA::revokeCertificate(const std::string& certPem, const std::string& revoked_at) {
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE certificates SET status = 'REVOKED', revoked_at = ? WHERE cert_pem = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, revoked_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, certPem.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}
bool dbCA::isRevokedCertificate(int userId) {
    const char* sql = "SELECT status FROM certificates WHERE user_id=? LIMIT 1;";
    std::cout << "[DB CA] Checking revocation status for userId=" << userId << "\n";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return true; // treat as revoked if query fails
    }

    sqlite3_bind_int(stmt, 1, userId);

    bool valid = true; // assume valid by default
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text) {
            std::string status = reinterpret_cast<const char*>(text);
            std::cout << "[DB CA] Revocation status for userId=" << userId << " is " << status << "\n";
            valid = (status == "valid");
        }
    }

    sqlite3_finalize(stmt);
    return valid;
}
bool dbCA::deleteUser(int userId) {
    sqlite3_stmt* stmt;
    const char* sql = "DELETE FROM users WHERE user_id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, userId);
    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
}
std::vector<CertificateRecord> dbCA::getRevokedCertificates() {
    std::vector<CertificateRecord> results;
    std::string sql = "SELECT * FROM certificates WHERE status='revoked';";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(CertificateRecord{
            sqlite3_column_int(stmt, 0),
            sqlite3_column_int(stmt, 1),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)),
            sqlite3_column_text(stmt, 7) ? std::optional<std::string>{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7))} : std::nullopt
        });
    }

    sqlite3_finalize(stmt);
    return results;
}
