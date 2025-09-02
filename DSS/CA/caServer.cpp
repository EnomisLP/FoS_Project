#include "caServer.h"
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
