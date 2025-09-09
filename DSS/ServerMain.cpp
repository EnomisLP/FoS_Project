#include "Protocol/secureChannelServer.h"
#include "Protocol/secureChannelCA.h"
#include "Protocol/secureChannelClient.h"
#include "Server/dssServer.h"
#include "CA/CA.h"
#include "CA/caServer.h"
#include "DB/db.h"
#include "Server/crypto.h"
#include <iostream>
#include <sstream>
#include <filesystem>

int main() {
    std::cout << "[MAIN] Starting server...\n";

    // --- Initialize DB ---
    std::cout << "[MAIN] Constructing DB...\n";
    db database("/home/simon/Projects/FoS_Project/DSS/db.db"); 
    if (!std::filesystem::exists("/home/simon/Projects/FoS_Project/DSS/db.db")) {
        std::cerr << "DB file missing!" << std::endl;
        exit(1);
    }
    std::cout << "[MAIN] DB initialized successfully.\n";

    // --- Initialize Crypto ---
    std::cout << "[MAIN] Constructing Crypto engine...\n";
    crypto cryptoEngine;
    std::cout << "[MAIN] Crypto engine initialized.\n";

    // --- Initialize Secure Channel Server ---
    std::cout << "[MAIN] Initializing SecureChannelServer...\n";
    secureChannelServer secureServer;

    if (!secureServer.initServerContext(
            "/home/simon/Projects/FoS_Project/DSS/Certifications/dss.crt",
            "/home/simon/Projects/FoS_Project/DSS/Certifications/dss.key",
            "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt")) {
        std::cerr << "[MAIN] ERROR: Failed to init TLS server context\n";
        return 1;
    }
    std::cout << "[MAIN] TLS server context initialized.\n";

    if (!secureServer.bindAndListen(5555)) {
        std::cerr << "[MAIN] ERROR: Failed to bind/listen on port 5555\n";
        return 1;
    }
    std::cout << "[SERVER] Listening on port 5555...\n";

  // --- Initialize CA Client ---
    std::cout << "[MAIN] Connecting to CA...\n";
    secureChannelClient secureCA;
    if (!secureCA.connectToCA("localhost", 4444, "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt")) {
        std::cerr << "[MAIN] ERROR: Failed to connect to CA server\n";
        return 1;
    }
    std::cout << "[MAIN] Connected to CA server.\n";

    // --- Initialize DSS Server Logic ---
    std::cout << "[MAIN] Constructing DSS server logic...\n";
    dssServer serverLogic(database, cryptoEngine, secureCA);
    std::cout << "[MAIN] DSS server logic ready.\n";

    // --- Main loop ---
    while (true) {
        std::cout << "[SERVER] Waiting for client...\n";
        if (!secureServer.acceptClient()) {
            std::cerr << "[SERVER] Failed to accept client\n";
            continue;
        }

        std::cout << "[SERVER] Client connected.\n";
        std::string currentUser;  // keep track of authenticated user

        while (true) {
            std::string request = secureServer.receiveData();
            if (request.empty()) {
                std::cout << "[SERVER] Client disconnected.\n";
                break;
            }

            std::cout << "[CLIENT] Request received: " << request << "\n";

            std::istringstream iss(request);
            std::string command;
            iss >> command;

            if (command == "AUTH") {
                std::string username, password;
                iss >> username >> password;

                std::string status = serverLogic.authenticate(username, password);
                
                if (status == "AUTH_OK" || status == "AUTH_ADMIN") {
                    currentUser = username;
                    std::cout << "[SERVER] Checking validity of stored certificate for user " << username << "\n";

                    auto userIdOpt = database.getUserId(username);
                    if (!userIdOpt) {
                        std::cerr << "[SERVER] User ID not found for " << username << "\n";
                        secureServer.sendData("AUTH_FAIL");
                        continue;
                    }
                    int userId = *userIdOpt;

                    // Check if a certificate exists in DB
                    auto certOpt = database.getCertificate(userId);
                    if (!certOpt) {
                        std::cout << "[SERVER] No certificate yet for " << username 
                        << " (probably hasn’t generated keys). Allowing login.\n";
                        secureServer.sendData(status); 
                        continue;
                    }

                    // Ask CA to validate the cert
                    secureCA.sendData("CHECK_CERT " + std::to_string(userId));
                    std::string response = secureCA.receiveData();
                    std::cout << "[SERVER] CA response for cert validity: " << response << "\n";

                    if (response == "CERT_VALID") {
                        std::cout << "[SERVER] Certificate valid for user " << username << "\n";
                        secureServer.sendData(status); // send the cert to client
                    } else {
                    std::cout << "[SERVER] Certificate invalid/revoked for " << username << " (CA response: " << response << ")\n";
                    currentUser.clear();
                    secureServer.sendData("AUTH_FAIL_CERT_INVALID");
                    }
                } else {
                    secureServer.sendData(status);
                }
            } else if (command == "FIRST_LOGIN") {
                std::string username, tempPassword, newPassword;
                iss >> username >> tempPassword >> newPassword;

                std::string status = serverLogic.authenticate(username, tempPassword);

                if (status != "FIRST_LOGIN") {
                    secureServer.sendData("FIRST_LOGIN_FAIL");
                    continue;
                }

                bool ok = serverLogic.handleChangePassword(username, newPassword);
                if (ok) {
                    currentUser = username;
                    secureServer.sendData("PASS_CHANGED");
                } else {
                    secureServer.sendData("FIRST_LOGIN_FAIL");
                }
            } else if (command == "REGISTER_USER") {
                std::string newUsername, tempPassword;
                iss >> newUsername >> tempPassword;

                std::string status = serverLogic.registerUser(newUsername, tempPassword);
                if (status == "USER_REGISTERED") {
                    secureServer.sendData("USER_REGISTERED");
                } else {
                    secureServer.sendData(status);
                }

            } else if (command == "CREATE_KEYS") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                std::string username, password;
                iss >> username >> password;
                bool ok = serverLogic.handleCreateKeys(currentUser, password);
                secureServer.sendData(ok ? "KEYS_CREATED" : "KEYS_FAILED");
            } else if (command == "SIGN_DOC") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                std::string password, username, path;
                iss >> username >> password >> path;
                bool ok = serverLogic.handleSignDoc(currentUser, password, path);
                secureServer.sendData(ok ? "SIGN_OK" : "SIGN_FAIL");

            } else if (command == "GET_CERTIFICATE") {
                std::string targetUser;
                iss >> targetUser;

                if (targetUser.empty()) {
                    secureServer.sendData("INVALID_REQUEST");
                    continue;
                }

                auto userIdOpt = database.getUserId(targetUser);
                if (!userIdOpt) {
                    secureServer.sendData("NO_USER");
                    continue;
                }
                int userId = *userIdOpt;

                // Retrieve certificate from DSS DB
                auto certOpt = serverLogic.handleGetCertificate(targetUser);
                if (!certOpt) {
                    std::cout << "[SERVER] No certificate found for user: " << targetUser << "\n";
                    secureServer.sendData("NO_CERT");
                    continue;
                }
                std::string certPem = *certOpt;
                std::cout << "[SERVER] Sending validation request to CA for user: " << targetUser << "\n";
                // Ask CA if certificate is still valid
                std::string caRequest = "CHECK_CERT " + std::to_string(userId) + "\n";
                if (!secureCA.sendData(caRequest)) {
                    secureServer.sendData("CERT_CHECK_FAIL");
                    continue;
                }

                std::string caResponse = secureCA.receiveData();
                std::cout << "[SERVER] CA response: " << caResponse << "\n";
                if (caResponse.empty()) {
                    secureServer.sendData("CERT_CHECK_FAIL");
                    continue;
                }

                if (caResponse == "CERT_VALID") {
                 // Only now send the actual certificate to the client
                    secureServer.sendData(certPem);
                } else {
                    secureServer.sendData(caResponse);
                }
            } else if (command == "DELETE_KEYS") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }

                bool ok = serverLogic.handleDeleteKeys(currentUser);
                secureServer.sendData(ok ? "DEL_OK" : "DEL_FAIL");
            } else {
                secureServer.sendData("UNKNOWN_COMMAND");
            }
        }
    }
}
