#include "caServer.h"
#include "CA.h"
#include <iostream>

// Constructor: store reference to CA instance
caServer::caServer(CA& caInstance) : ca(caInstance) {}

// Handle CSR request from DSS and return signed certificate
std::string caServer::handleRequestCertificate(const std::string& csrPem) {
    if (csrPem.empty()) {
        std::cerr << "[CA SERVER] Empty CSR received\n";
        return "";
    }

    std::string certPem = ca.signCSR(csrPem, 365); // 1-year validity

    if (certPem.empty()) {
        std::cerr << "[CA SERVER] Failed to sign CSR\n";
        return "";
    }

    std::cout << "[CA SERVER] CSR signed successfully\n";
    return certPem;
}
bool caServer::handleRevokeCertificate(const std::string& serial) {
    if (serial.empty()) {
        std::cerr << "[CA SERVER] Empty serial received for revocation\n";
        return false;
    }

    bool success = ca.revokeCert(serial);
    if (success) {
        std::cout << "[CA SERVER] Certificate with serial " << serial << " revoked successfully\n";
    } else {
        std::cerr << "[CA SERVER] Failed to revoke certificate with serial " << serial << "\n";
    }
    return success;
}
