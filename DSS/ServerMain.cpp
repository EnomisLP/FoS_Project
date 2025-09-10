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
    secureChannelServer secureServer(database);

    if (!secureServer.initServerContext(
            "/home/simon/Projects/FoS_Project/DSS/Certifications/dss.crt",
            "/home/simon/Projects/FoS_Project/DSS/Certifications/dss.key",
            "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt",
            database)) {
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
    secureChannelClient secureCA(database);
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
    std::string currentUser;  // authenticated session

    while (true) {
        std::string request = secureServer.receiveData();
        if (request.empty()) {
            std::cout << "[SERVER] Client disconnected.\n";
            break;
        }

        std::cout << "[CLIENT] Request received: " << request << "\n";

        // --- Extract payload, timestamp, nonce ---
        auto last_space = request.find_last_of(' ');
        auto second_last_space = request.find_last_of(' ', last_space - 1);
        if (last_space == std::string::npos || second_last_space == std::string::npos) {
            secureServer.sendData("MALFORMED_REQUEST");
            continue;
        }

        std::string nonce = request.substr(last_space + 1);
        std::string ts_str = request.substr(second_last_space + 1, last_space - second_last_space - 1);
        std::string payload = request.substr(0, second_last_space);

        long ts = 0;
        try { ts = std::stol(ts_str); } catch(...) { secureServer.sendData("INVALID_TIMESTAMP"); continue; }

        // --- Timestamp freshness check ---
        const int ALLOWED_SKEW = 300; // seconds
        long now = std::time(nullptr);
        if (std::llabs(now - ts) > ALLOWED_SKEW) {
            secureServer.sendData("ERROR_TS");
            continue;
        }

        // --- Replay check ---
        std::string owner = currentUser.empty() ? "ANONYMOUS" : currentUser;
        if (!database.storeNonceIfFresh(owner, nonce, ALLOWED_SKEW)) {
            secureServer.sendData("REPLAY_DETECTED");
            continue;
        }

        // --- Parse command ---
        std::istringstream iss(payload);
        std::string command;
        iss >> command;

        // ================= AUTH =================
        if (command == "AUTH") {
            std::string username, password;
            iss >> username >> password;

            std::string status = serverLogic.authenticate(username, password);

            if (status == "AUTH_OK" || status == "AUTH_ADMIN") {
                currentUser = username;

                auto userIdOpt = database.getUserId(username);
                if (!userIdOpt) { secureServer.sendData("AUTH_FAIL"); continue; }
                int userId = *userIdOpt;

                auto certOpt = database.getCertificate(userId);
                if (!certOpt) {
                    secureServer.sendData(status); // allow login if no cert yet
                    continue;
                }

                // DSS -> CA check
                std::string caPayload = "CHECK_CERT " + std::to_string(userId);
                if (!secureCA.sendWithNonce("DSS->CA", caPayload, 300)) {
                    secureServer.sendData("CERT_CHECK_FAIL");
                    continue;
                }

                std::string caResponse = secureCA.receiveAndVerifyNonce("CA->DSS");
                std::cout << "[SERVER] CA response: " << caResponse << "\n";

                if (caResponse == "CERT_VALID") {
                    secureServer.sendData(status);
                } else {
                    currentUser.clear();
                    secureServer.sendData("AUTH_FAIL_CERT_INVALID");
                }
            } else {
                secureServer.sendData(status);
            }

        // ================= FIRST_LOGIN =================
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

        // ================= REGISTER_USER =================
        } else if (command == "REGISTER_USER") {
            std::string newUsername, tempPassword;
            iss >> newUsername >> tempPassword;

            std::string status = serverLogic.registerUser(newUsername, tempPassword);
            secureServer.sendData(status == "USER_REGISTERED" ? "USER_REGISTERED" : status);

        // ================= CREATE_KEYS =================
        } else if (command == "CREATE_KEYS") {
            if (currentUser.empty()) { secureServer.sendData("NOT_AUTHENTICATED"); continue; }
            std::string username, password;
            iss >> username >> password;
            bool ok = serverLogic.handleCreateKeys(currentUser, password);
            secureServer.sendData(ok ? "KEYS_CREATED" : "KEYS_FAILED");

        // ================= SIGN_DOC =================
        } else if (command == "SIGN_DOC") {
            if (currentUser.empty()) { secureServer.sendData("NOT_AUTHENTICATED"); continue; }
            std::string username, password, path;
            iss >> username >> password >> path;
            bool ok = serverLogic.handleSignDoc(currentUser, password, path);
            secureServer.sendData(ok ? "SIGN_OK" : "SIGN_FAIL");

        // ================= GET_CERTIFICATE =================
        } else if (command == "GET_CERTIFICATE") {
            std::string targetUser;
            iss >> targetUser;
            if (targetUser.empty()) { secureServer.sendData("INVALID_REQUEST"); continue; }

            auto userIdOpt = database.getUserId(targetUser);
            if (!userIdOpt) { secureServer.sendData("NO_USER"); continue; }
            int userId = *userIdOpt;

            auto certOpt = serverLogic.handleGetCertificate(targetUser);
            if (!certOpt) { secureServer.sendData("NO_CERT"); continue; }

            std::string caPayload = "CHECK_CERT " + std::to_string(userId);
            if (!secureCA.sendWithNonce("DSS->CA", caPayload, 300)) { secureServer.sendData("CERT_CHECK_FAIL"); continue; }

            std::string caResponse = secureCA.receiveAndVerifyNonce("CA->DSS");
            if (caResponse == "CERT_VALID") {
                secureServer.sendData(*certOpt);
            } else {
                secureServer.sendData(caResponse);
            }

        // ================= DELETE_KEYS =================
        } else if (command == "DELETE_KEYS") {
            if (currentUser.empty()) { secureServer.sendData("NOT_AUTHENTICATED"); continue; }
            bool ok = serverLogic.handleDeleteKeys(currentUser);
            secureServer.sendData(ok ? "DEL_OK" : "DEL_FAIL");

        // ================= UNKNOWN =================
        } else {
            secureServer.sendData("UNKNOWN_COMMAND");
        }
    }
    }
}
