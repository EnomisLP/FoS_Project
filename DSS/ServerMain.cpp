#include "Protocol/secureChannelServer.h"
#include "Server/dssServer.h"
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

    // --- Initialize DSS Server Logic ---
    std::cout << "[MAIN] Constructing DSS server logic...\n";
    dssServer serverLogic(database, cryptoEngine);
    std::cout << "[MAIN] DSS server logic ready.\n";

    // --- Initialize Secure Channel Server ---
    std::cout << "[MAIN] Initializing SecureChannelServer...\n";
    secureChannelServer secureServer;

    if (!secureServer.initServerContext(
            "/home/simon/Projects/FoS_Project/DSS/Certifications/server.crt",
            "/home/simon/Projects/FoS_Project/DSS/Certifications/server.key",
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
            if (command == "FIRST_LOGIN") {
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
            }

            } else if (command == "CREATE_KEYS") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                bool ok = serverLogic.handleCreateKeys(currentUser);
                secureServer.sendData(ok ? "KEYS_CREATED" : "KEYS_FAILED");

            } else if (command == "SIGN_DOC") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
            std::string document;
            std::getline(iss, document);
            auto sig = serverLogic.handleSignDoc(currentUser, document);
            secureServer.sendData(sig ? *sig : "SIGN_FAIL");

            } else if (command == "GET_PUBLIC_KEY") {
                std::string targetUser;
                iss >> targetUser;
                auto pubKey = serverLogic.handleGetPublicKey(targetUser);
                secureServer.sendData(pubKey ? *pubKey : "NO_KEY");

            } else if (command == "DELETE_KEYS") {
                if (currentUser.empty()) {
                    secureServer.sendData("NOT_AUTHENTICATED");
                    continue;
                }
                bool ok = serverLogic.handleDeleteKeys(currentUser);
                secureServer.sendData(ok ? "KEYS_DELETED" : "DELETE_FAILED");

            } else {
                secureServer.sendData("UNKNOWN_COMMAND");
            }
        }
    }
}
