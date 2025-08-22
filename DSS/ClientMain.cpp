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
    std::string username, password;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    if (!myClient.authenticate(username, password)) {
        std::cerr << "Authentication failed\n";
        return 1;
    }

    std::cout << "[Client] Authenticated successfully.\n";

    // Menu loop
    int choice;
    do {
        std::cout << "\n=== Client Menu ===\n";
        std::cout << "1. Create Keys\n";
        std::cout << "2. Sign Document\n";
        std::cout << "3. Get Public Key\n";
        std::cout << "4. Delete Keys\n";
        std::cout << "0. Exit\n";
        std::cout << "Choose an option: ";
        std::cin >> choice;

        switch (choice) {
            case 1: {
                if (myClient.requestCreateKeys()) {
                    std::cout << "[Client] Keys created.\n";
                } else {
                    std::cout << "[Client] Failed to create keys.\n";
                }
                break;
            }
            case 2: {
                std::cin.ignore(); // pulisce il buffer
                std::string document;
                std::cout << "Enter document to sign: ";
                std::getline(std::cin, document);

                if (myClient.requestSignDoc(document)) {
                    std::cout << "[Client] Document signed successfully.\n";
                } else {
                    std::cout << "[Client] Failed to sign document.\n";
                }
                break;
            }
            case 3: {
                std::string targetUser;
                std::cout << "Enter username to get public key: ";
                std::cin >> targetUser;
                std::string pubkey = myClient.requestGetPublicKey(targetUser);
                std::cout << "[Client] Public Key: \n" << pubkey << "\n";
                break;
            }
            case 4: {
                if (myClient.requestDeleteKeys()) {
                    std::cout << "[Client] Keys deleted.\n";
                } else {
                    std::cout << "[Client] Failed to delete keys.\n";
                }
                break;
            }
            case 0:
                std::cout << "Exiting...\n";
                break;
            default:
                std::cout << "Invalid option. Try again.\n";
        }

    } while (choice != 0);

    return 0;
}
