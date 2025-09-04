#include "caServer.h"
#include "CA.h"
#include <iostream>
#include <optional>
#include <string>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>


// Constructor: store reference to CA instance
caServer::caServer(CA& caInstance, dbCA& dbInstance) : ca(caInstance), db(dbInstance) {}
//Utilities for time formatting
// Returns current UTC time as YYYY-MM-DD HH:MM:SS
inline std::string caServer::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Returns expiry time after N days
inline std::string caServer::getExpiryTime(int days) {
    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(24 * days);
    std::time_t t = std::chrono::system_clock::to_time_t(expiry);

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
// Handle CSR request from DSS and return signed certificate
std::string caServer::handleRequestCertificate(int user_id, const std::string& csrPem) {
    // 1. Sign CSR
    auto certPem = ca.signCSR(csrPem);
    if (certPem.empty()) {
        std::cerr << "[CA] Failed to sign CSR for user " << user_id << "\n";
        return "";
    }

    // 2. Generate serial number (unique)
    std::string serial = ca.generateSerial();

    // 3. Issue/expiry times
    std::string issuedAt = getCurrentTime();
    std::string expiresAt = getExpiryTime(365); // 1 year validity

    // 4. Get user_id from DB (CA can maintain its own user table, or rely on DSS passing user_id)
    int dummyUserId = 0; // You can expand later if CA manages identities too

    // 5. Store in CA DB
    if (!db.storeCertificate(user_id, certPem, serial, issuedAt, expiresAt)) {
        std::cerr << "[CA] Failed to store cert for " << user_id << "\n";
        return "";
    }

    std::cout << "[CA] Certificate issued for " << user_id
              << " (serial=" << serial << ")\n";
    return serial;
}

bool caServer::handleRevokeCertificate(int user_id, const std::string& serial) {
     // 1. Fetch certificate from DB by userId
    std::string certEntry = db.getSerialByUser(user_id);
    if (certEntry.empty()) {
        std::cerr << "[CA] No certificate found for userId=" << user_id << "\n";
        return false;
    }

    // 2. Check serial matches
    if (certEntry != serial) {
        std::cerr << "[CA] Serial mismatch for userId=" << user_id
                  << " (expected=" << certEntry
                  << ", got=" << serial << ")\n";
        return false;
    }
    std::string revokedAt = getCurrentTime();
    // 3. Mark certificate as revoked
    if (!db.revokeCertificate(serial, revokedAt)) {
        std::cerr << "[CA] Failed to revoke certificate serial=" << serial << "\n";
        return false;
    }

    // 4. Remove user from DB
    if (!db.deleteUser(user_id)) {
        std::cerr << "[CA] Failed to delete userId=" << user_id << " after revocation\n";
        return false;
    }

    std::cout << "[CA] Revoked certificate serial=" << serial
              << " and removed userId=" << user_id << "\n";
    return true;
}
