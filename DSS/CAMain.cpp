#include "CA.h"
#include "DB/dbCA.h"
#include "caServer.h"
#include "Protocol/secureChannelCA.h"
#include <iostream>
#include <sstream>
#include <string>
#include <arpa/inet.h> // For htonl/ntohl
// Utility functions for sending/receiving length-prefixed strings
bool sendString(SSL* ssl, const std::string& data) {
    uint32_t len = htonl(data.size());
    if (SSL_write(ssl, &len, sizeof(len)) <= 0) return false;
    size_t offset = 0;
    while (offset < data.size()) {
        int ret = SSL_write(ssl, data.data() + offset, data.size() - offset);
        if (ret <= 0) return false;
        offset += ret;
    }
    return true;
}

std::string receiveString(SSL* ssl) {
    uint32_t len = 0;
    int ret = SSL_read(ssl, &len, sizeof(len));
    if (ret <= 0) return {};
    len = ntohl(len);
    std::string buffer(len, 0);
    size_t offset = 0;
    while (offset < len) {
        ret = SSL_read(ssl, buffer.data() + offset, len - offset);
        if (ret <= 0) return {};
        offset += ret;
    }
    return buffer;
}
int main() {
    std::cout << "[CA Server] Starting...\n";

    // --- Initialize CA ---
    CA ca("/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.key",
          "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.crt");

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
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt",  
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.key",  
        "/home/simon/Projects/FoS_Project/DSS/Certifications/ca_server.crt"   
    )) 
    {
        std::cerr << "[CA Server] ERROR: Failed to init TLS context\n";
        return 1;
    }
    std::cout << "[CA Server] CA initialized successfully.\n";

    // --- Start secure server ---

    if (!channel.bindAndListen(4444)) {
        std::cerr << "[CA Server] ERROR: Failed to bind/listen on port 4444\n";
        return 1;
    }

    std::cout << "[CA Server] Listening on port 4444...\n";

 // 3. Main loop
   while (true) {
        std::cout << "[CA Server] Waiting for DSS connection...\n";
        if (!channel.acceptConnection()) {
            std::cerr << "[CA Server] Failed to accept DSS connection.\n";
            continue;
        }

        std::cout << "[CA Server] DSS connected.\n";

        std::string request = channel.receiveData(); // read full request
        if (request.empty()) {
            std::cerr << "[CA Server] Empty request.\n";
            continue;
        }

        std::istringstream iss(request);
        std::string cmd;
        iss >> cmd;

        if (cmd == "REQ_CERT") {
            std::cout << "[CA Server] Certificate request received.\n";
            int userId;
            iss >> userId;
            std::string csrPem = request.substr(cmd.size() + std::to_string(userId).size() + 2); // skip "REQ_CERT userId "
            std::string response = server.handleRequestCertificate(userId, csrPem);
            if (response.empty()) response = "ERROR";
            channel.sendData(response);
        }
        else if (cmd == "REVOKE_CERT") {
            std::cout << "[CA Server] Revoke certificate request received.\n";
            int userId;
            iss >> userId;
            std::string certPem = request.substr(cmd.size() + std::to_string(userId).size() + 2);
            bool ok = server.handleRevokeCertificate(userId, certPem);
            channel.sendData(ok ? "REVOKE_OK" : "REVOKE_FAIL");
        }
        else if (cmd == "CHECK_CERT") {
            std::cout << "[CA Server] Check certificate request received.\n";
            int userId;
            iss >> userId;
            bool valid = server.handleCheckCertificate(userId);
            channel.sendData(valid ? "CERT_VALID" : "CERT_INVALID");
        }
        else {
            channel.sendData("UNKNOWN_COMMAND");
        }
    }
}

