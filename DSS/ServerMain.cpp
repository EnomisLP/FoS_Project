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

    // --- Migrate offline users ---
    std::cout << "[MAIN] Migrating offline users to DB if any...\n";
    serverLogic.migrateOfflineUsersToDB();
    
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
        std::string request = secureServer.receiveData();
        std::cout << "[CLIENT] Request received: " << request << "\n";

        std::istringstream iss(request);
        std::string command;
        iss >> command;

        if (command == "AUTH") {
            std::string username, password_hash;
            iss >> username >> password_hash;
            bool ok = serverLogic.authenticate(username, password_hash);
            secureServer.sendData(ok ? "AUTH_OK" : "AUTH_FAIL");

        } else if (command == "FIRST_LOGIN") {
            std::string username, tempPassword, newPassword;
            iss >> username >> tempPassword >> newPassword;

            // Verify temporary password exists in DB (or JSON already loaded by client)
            if (!serverLogic.authenticate(username, tempPassword)) {
                secureServer.sendData("FIRST_LOGIN_FAIL");
                continue;
            }

            // Add user to database with new password
            bool ok = serverLogic.handleChangePassword(username, newPassword);
            secureServer.sendData(ok ? "PASS_CHANGED" : "FIRST_LOGIN_FAIL");

        } else if (command == "CREATE_KEYS") {
            std::string username;
            iss >> username;
            bool ok = serverLogic.handleCreateKeys(username);
            secureServer.sendData(ok ? "KEYS_CREATED" : "KEYS_FAILED");

        } else if (command == "SIGN_DOC") {
            std::string username;
            iss >> username;
            std::string document;
            std::getline(iss, document);
            auto sig = serverLogic.handleSignDoc(username, document);
            secureServer.sendData(sig ? *sig : "SIGN_FAIL");

        } else if (command == "GET_PUBLIC_KEY") {
            std::string username;
            iss >> username;
            auto pubKey = serverLogic.handleGetPublicKey(username);
            secureServer.sendData(pubKey ? *pubKey : "NO_KEY");

        } else if (command == "DELETE_KEYS") {
            std::string username;
            iss >> username;
            bool ok = serverLogic.handleDeleteKeys(username);
            secureServer.sendData(ok ? "KEYS_DELETED" : "DELETE_FAILED");

        } else {
            secureServer.sendData("UNKNOWN_COMMAND");
        }
    }

}
