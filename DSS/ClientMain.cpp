#include "Client/client.h"
#include "Protocol/secureChannelClient.h"
#include <iostream>
#include <sstream>

int main() {
    client myClient("localhost", 5555, "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt");

    if (!myClient.connectToServer()) {
        std::cerr << "Failed to connect securely to the server\n";
        return 1;
    }

    std::cout << "[Client] Connected securely.\n";

    // Example authentication
    if (!myClient.authenticate("simone", "example_hash_1")) {
        std::cerr << "Authentication failed\n";
        return 1;
    }

    std::cout << "[Client] Authenticated successfully.\n";

    // Request key generation
    if (myClient.requestCreateKeys()) {
        std::cout << "[Client] Keys created.\n";
    }

    // Request signing
    myClient.requestSignDoc("This is a test document");

    // Get public key
    std::string pubkey = myClient.requestGetPublicKey("simone");
    std::cout << "[Client] Public Key: \n" << pubkey << "\n";

    // Delete keys
    myClient.requestDeleteKeys();

    return 0;
}
