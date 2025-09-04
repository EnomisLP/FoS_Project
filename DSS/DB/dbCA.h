#pragma once
#include <string>
#include <optional>
#include <vector>
#include <sqlite3.h>

struct CertificateRecord {
    int id;
    int user_id;
    std::string cert_pem;
    std::string serial_number;
    std::string issued_at;
    std::string expires_at;
    std::string status;      // "valid", "revoked", "expired"
    std::optional<std::string> revoked_at;
};

class dbCA {
public:
    dbCA(const std::string& dbPath);
    ~dbCA();

    bool initDB();

    bool storeCertificate(int user_id,
                          const std::string& cert_pem,
                          const std::string& serial_number,
                          const std::string& issued_at,
                          const std::string& expires_at);

    bool revokeCertificate(const std::string& serial_number,
                           const std::string& revoked_at);
    bool deleteUser(int userId);
    std::string getSerialByUser(int userId);
    std::optional<CertificateRecord> getCertificate(const std::string& serial_number);
    std::vector<CertificateRecord> getAllCertificates();
    std::vector<CertificateRecord> getRevokedCertificates();

private:
    std::string dbPath;
    sqlite3* db;

    bool execute(const std::string& sql);
};
