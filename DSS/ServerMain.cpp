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
    dssServer serverLogic(database, cryptoEngine, "localhost", 4444);
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
                }
                secureServer.sendData(status);
            } else if (command == "FIRST_LOGIN") {
                std::string username, tempPassword, newPassword;
                iss >> username >> tempPassword >> newPassword;

                std::string status = serverLogic.authenticate(username, tempPassword);

                if (status != "FIRST_LOGIN" && status != "AUTH_OK" && status != "AUTH_ADMIN") {
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
            }   
            else if(command == "REGISTER_USER"){
                std::string newUsername, tempPassword;
                iss >> newUsername >> tempPassword;

                std::string status = serverLogic.registerUser(newUsername, tempPassword);
                if (status == "USER_REGISTERED") {
                    secureServer.sendData("USER_REGISTERED");
                } else {
                    secureServer.sendData(status);
                }

            } else if (command == "REQ_CERT") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }

                std::string csrPem;
                std::string username;
                iss >> username;  
                std::getline(iss, csrPem);

                int userId = database.getUserId(username) ? *database.getUserId(username) : -1;
                if (userId == -1) {
                    secureServer.sendData("KEYS_FAILED");
                    continue;
                }
                std::string caRequest = "REQ_CERT " + std::to_string(userId) + " " + csrPem;
                secureCA.sendData(caRequest);

                std::string serial = secureCA.receiveData();
                if (serial.empty() || serial == "ERROR") {
                    std::cerr << "[DSS] Failed to get certificate from CA\n";
                    secureServer.sendData("KEYS_FAILED");
                    continue;
                }

                std::cout << "[DSS] Certificate received from CA for user: " << username << "\n";
                bool ok = serverLogic.handleCreateKeys(username, serial);
                secureServer.sendData(ok ? serial : "KEYS_FAILED");
            } else if (command == "SIGN_DOC") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                std::string document;
                std::getline(iss, document);
                auto sig = serverLogic.handleSignDoc(currentUser, document);
                secureServer.sendData(sig ? *sig : "SIGN_FAIL");

            } else if (command == "GET_CERTIFICATE") {
                std::string targetUser;
                iss >> targetUser;
                int userId = database.getUserId(targetUser) ? *database.getUserId(targetUser) : -1;
                if (userId == -1) {
                    secureServer.sendData("NO_CERT");
                    continue;
                }
                auto cert = serverLogic.handleGetCertificate(targetUser);
                secureServer.sendData("CHECK_CERT " + std::to_string(userId));
                std::string response = secureCA.receiveData();
                if(response == "CERT_VALID") {
                    secureServer.sendData(cert ? *cert : "NO_CERT");
                } else {
                    secureServer.sendData("CERT_INVALID");
                }

            } else if (command == "DELETE_KEYS") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                std::string userId = database.getUserId(currentUser) ? std::to_string(*database.getUserId(currentUser)) : "UNKNOWN";
                if (userId == "UNKNOWN") {
                    secureServer.sendData("DEL_FAIL");
                    continue;
                }
                std::optional<std::string> certPem = database.getCertificate(currentUser);
                std::string request = "REVOKE_CERT " + userId + " " + (certPem ? *certPem : "");
                secureCA.sendData(request);
                std::string response = secureCA.receiveData();
                if(response == "REVOKE_OK") {
                    bool ok = serverLogic.handleDeleteKeys(currentUser);
                    secureServer.sendData(ok ? "DEL_OK" : "DEL_FAIL");
                } else {
                    secureServer.sendData(response);
                }

            } else {
                secureServer.sendData("UNKNOWN_COMMAND");
            }
        }
    }
}
