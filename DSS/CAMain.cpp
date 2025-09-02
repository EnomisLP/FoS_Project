#include "CA.h"
#include "caServer.h"
#include "Protocol/secureChannelCA.h"
#include <iostream>
#include <string>

int main() {
    std::cout << "[CA SERVER] Starting...\n";

    // --- Initialize CA ---
    CA ca("/home/simon/Projects/FoS_Project/DSS/Certifications/ca.key",
          "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt");

    if (!ca.init()) {
        std::cerr << "[CA SERVER] ERROR: Failed to initialize CA\n";
        return 1;
    }
    caServer server(ca);
    std::cout << "[CA SERVER] CA initialized successfully.\n";

    // --- Start secure server ---
    secureChannelCA channel;
    if (!channel.initCAContext(
            "/home/simon/Projects/FoS_Project/DSS/Certifications/server.crt",  // server cert
            "/home/simon/Projects/FoS_Project/DSS/Certifications/server.key",  // server key
            "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt"   // CA cert
        )) 
    {
        std::cerr << "[CA SERVER] ERROR: Failed to init TLS context\n";
        return 1;
    }

    if (!channel.bindAndListen(4444)) {
        std::cerr << "[CA SERVER] ERROR: Failed to bind/listen on port 4444\n";
        return 1;
    }

    std::cout << "[CA SERVER] Listening on port 4444...\n";

 // 3. Main loop
    while (true) {
        std::cout << "[CA SERVER] Waiting for DSS connection...\n";
        if (!channel.acceptConnection()) {
            std::cerr << "[CA SERVER] Failed to accept DSS connection.\n";
            continue;
        }

        std::cout << "[CA SERVER] DSS connected.\n";

        std::string request = channel.receiveData();
        if (request.empty()) {
            std::cerr << "[CA SERVER] Empty request.\n";
            continue;
        }

        if (request.rfind("REQ_CERT", 0) == 0) {
            std::string csrPem = request.substr(8); 
            std::string response = server.handleRequestCertificate(csrPem);
            if (response.empty()) {
                response = "ERROR";
            }
            channel.sendData(response);
        } else {
            channel.sendData("UNKNOWN_COMMAND");
        }
    }
}
