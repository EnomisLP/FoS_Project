#include "Protocol/secureChannelServer.h"
#include "Server/dssServer.h"
#include "DB/db.h"
#include "Server/crypto.h"
#include <iostream>
#include <sstream>

int main() {
    // Init DB and Crypto
    db database("db.db"); // Adjust DB path as needed
    crypto cryptoEngine;
    dssServer serverLogic(database, cryptoEngine);

    // Init secure server
    secureChannelServer secureServer;
    if (!secureServer.initServerContext(
    "/home/simon/Projects/FoS_Project/DSS/Certifications/server.crt",
    "/home/simon/Projects/FoS_Project/DSS/Certifications/server.key",
    "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt")) {
        std::cerr << "Failed to init TLS server context\n";
        return 1;
    }
    if (!secureServer.bindAndListen(5555)) {
        std::cerr << "Failed to bind/listen on port\n";
        return 1;
    }

    std::cout << "[Server] Listening on port 5555...\n";

    while (true) {
        if (!secureServer.acceptClient()) {
            std::cerr << "[Server] Failed to accept client\n";
            continue;
        }

        std::string request = secureServer.receiveData();
        std::cout << "[Client] " << request << "\n";

        std::istringstream iss(request);
        std::string command;
        iss >> command;

        if (command == "AUTH") {
            std::string username, password_hash;
            iss >> username >> password_hash;
            bool ok = serverLogic.authenticate(username, password_hash);
            secureServer.sendData(ok ? "AUTH_OK" : "AUTH_FAIL");

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
