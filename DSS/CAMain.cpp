#include "CA.h"
#include "DB/dbCA.h"
#include "caServer.h"
#include "Protocol/secureChannelCA.h"
#include <iostream>
#include <sstream>
#include <string>
#include <arpa/inet.h> // For htonl/ntohl

int main() {
    std::cout << "[CA Server] Starting...\n";

    // --- Initialize CA ---
    CA ca(
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.key",
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.crt"
    );

    if (!ca.init()) {
        std::cerr << "[CA Server] ERROR: Failed to initialize CA\n";
        return 1;
    }
    std::cout << "[CA Server] CA initialized successfully.\n";

    // --- Initialize Database ---
    dbCA database("/home/simon/Projects/FoS_Project/DSS/DB/dbCA.db");
    if (!database.initDB()) {
        std::cerr << "[CA Server] ERROR: Failed to initialize database\n";
        return 1;
    }
    std::cout << "[CA Server] Database initialized successfully.\n";

    // --- Initialize Secure Channel ---
    caServer server(ca, database);
    secureChannelCA channel;
    if (!channel.initCAContext(
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt",        // Root CA cert
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.key", // Private key
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.crt"  // Server cert
    )) {
        std::cerr << "[CA Server] ERROR: Failed to init TLS context\n";
        return 1;
    }
    std::cout << "[CA Server] TLS context initialized successfully.\n";

    // --- Start secure server ---
    if (!channel.bindAndListen(4444)) {
        std::cerr << "[CA Server] ERROR: Failed to bind/listen on port 4444\n";
        return 1;
    }
    std::cout << "[CA Server] Listening on port 4444...\n";

    // --- Main loop ---
    while (true) {
        std::cout << "[CA Server] Waiting for DSS connection...\n";
        if (!channel.acceptConnection()) {
            std::cerr << "[CA Server] Failed to accept DSS connection.\n";
            continue;
        }

        std::cout << "[CA Server] DSS connected.\n";

        // Process multiple requests from this DSS client
        while (true) {
            std::string request = channel.receiveData();
            if (request.empty()) {
                std::cerr << "[CA Server] Connection closed or empty request.\n";
                break; // break inner loop → wait for next DSS connection
            }

            std::istringstream iss(request);
            std::string cmd;
            iss >> cmd;

            if (cmd == "REQ_CERT") {
                std::cout << "[CA Server] Certificate request received.\n";
                int userId;
                iss >> userId;
                std::string csrPem = request.substr(
                    cmd.size() + std::to_string(userId).size() + 2
                );
                std::string response = server.handleRequestCertificate(userId, csrPem);
                if (response.empty()) response = "ERROR";
                channel.sendData(response);
                continue;
            }
            else if (cmd == "REVOKE_CERT") {
                std::cout << "[CA Server] Revoke certificate request received.\n";
                int userId;
                iss >> userId;
                std::string certPem = request.substr(
                    cmd.size() + std::to_string(userId).size() + 2
                );
                bool ok = server.handleRevokeCertificate(userId, certPem);
                channel.sendData(ok ? "REVOKE_OK" : "REVOKE_FAIL");
                continue;
            }
            else if (cmd == "CHECK_CERT") {
                std::cout << "[CA Server] Check certificate request received.\n";
                int userId;
                iss >> userId;
                bool valid = server.handleCheckCertificate(userId);
                channel.sendData(valid ? "CERT_VALID" : "CERT_INVALID");
                continue;
            }
            else {
                std::cerr << "[CA Server] Unknown command: " << cmd << "\n";
                channel.sendData("UNKNOWN_COMMAND");
                continue;
            }
        }
    }
}
