#include "dbCA.h"
#include <iostream>
#include <sstream>

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
    return execute(sql);
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

std::string dbCA::getSerialByUser(int userId) {
    std::string sql = "SELECT serial_number FROM certificates WHERE user_id=? AND status='valid' LIMIT 1;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return "";

    sqlite3_bind_int(stmt, 1, userId);

    std::string serial;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        serial = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }

    sqlite3_finalize(stmt);
    return serial;
}
bool dbCA::revokeCertificate(const std::string& serial_number, const std::string& revoked_at) {
    sqlite3_stmt* stmt;
    const char* sql = "UPDATE certificates SET status = 'REVOKED', revoked_at = ? WHERE serial_number = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, revoked_at.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, serial_number.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    return ok;
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
