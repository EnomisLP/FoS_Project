#include "Client/client.h"
#include "Protocol/secureChannelClient.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <nlohmann/json.hpp>

// ---------------- Random Password Generator ----------------
std::string generateRandomPassword(int length = 12) {
    const std::string chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);

    std::string pass;
    for (int i = 0; i < length; ++i) {
        pass += chars[dis(gen)];
    }
    return pass;
}

// ---------------- Load Server Public Key ----------------
std::string loadServerPublicKey(const std::string& path) {
    std::ifstream pubKeyFile(path);
    if (!pubKeyFile.is_open()) {
        std::cerr << "Failed to open server public key file: " << path << "\n";
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(pubKeyFile)),
                        std::istreambuf_iterator<char>());
}

// ---------------- Client Menu Loop ----------------
void runClientMenu(client& myClient) {
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
                myClient.channel.sendData("CREATE_KEYS");
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response] " << response << "\n";
                break;
            }
            case 2: {
                std::cin.ignore();
                std::string document;
                std::cout << "Enter document to sign: ";
                std::getline(std::cin, document);

                myClient.channel.sendData("SIGN_DOC " + document);
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response] " << response << "\n";
                break;
            }
            case 3: {
                std::string targetUser;
                std::cout << "Enter username to get public key: ";
                std::cin >> targetUser;

                myClient.channel.sendData("GET_PUBLIC_KEY " + targetUser);
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response]\n" << response << "\n";
                break;
            }
            case 4: {
                myClient.channel.sendData("DELETE_KEYS");
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response] " << response << "\n";
                break;
            }
            case 0:
                std::cout << "Exiting...\n";
                break;
            default:
                std::cout << "Invalid option. Try again.\n";
        }
    } while (choice != 0);
}

// ---------------- Main ----------------
int main() {
    std::cout << "[Client] Starting client...\n";
    std::cout << "[Client] Select mode:\n";
    std::cout << "1. Offline registration\n";
    std::cout << "2. Connect to server\n";
    int option;
    std::cin >> option;

    const std::string offlineFile = "/home/simon/Projects/FoS_Project/DSS/DB/offline_users.json";
    const std::string serverPubKeyFile = "/home/simon/Projects/FoS_Project/DSS/Certifications/server.crt";

    if (option == 1) {
        nlohmann::json offlineUsers;
        std::ifstream inFile(offlineFile);
        if (inFile.is_open()) {
            inFile >> offlineUsers;
            inFile.close();
        }

        std::string username;
        std::cout << "Enter username for offline registration: ";
        std::cin >> username;

        if (offlineUsers.contains(username)) {
            std::cerr << "Username already registered offline.\n";
            return 1;
        }

        std::string tempPassword = generateRandomPassword();
        std::string serverPubKey = loadServerPublicKey(serverPubKeyFile);
        if (serverPubKey.empty()) return 1;

        offlineUsers[username] = {
            {"temp_password", tempPassword},
            {"server_pubkey", serverPubKey}
        };

        std::ofstream outFile(offlineFile);
        if (!outFile.is_open()) {
            std::cerr << "Failed to write offline_users.json\n";
            return 1;
        }
        outFile << offlineUsers.dump(4);
        outFile.close();

        std::cout << "[Client] Offline registration completed.\n";
        std::cout << "Username: " << username << "\n";
        std::cout << "Temporary password: " << tempPassword << "\n";

        return 0;
    }
    else if (option == 2) {
        client myClient("localhost", 5555, "/home/simon/Projects/FoS_Project/DSS/Certifications/ca.crt");
        if (!myClient.connectToServer()) {
            std::cerr << "Failed to connect securely to the server\n";
            return 1;
        }
        std::cout << "[Client] Connected securely.\n";

        int loginOption;
        std::cout << "Select login type:\n";
        std::cout << "1. Normal login\n";
        std::cout << "2. First login with temporary password\n";
        std::cin >> loginOption;

        if (loginOption == 1) {
            std::string username, password;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter password: ";
            std::cin >> password;

            myClient.channel.sendData("AUTH " + username + " " + password);
            std::string response = myClient.channel.receiveData();

            if (response != "AUTH_OK") {
                std::cerr << "Authentication failed\n";
                return 1;
            }
            std::cout << "[Client] Authenticated successfully.\n";
            runClientMenu(myClient);
        }
        else if (loginOption == 2) {
            std::string username, tempPassword, newPassword;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter temporary password: ";
            std::cin >> tempPassword;
            std::cout << "Enter new password: ";
            std::cin >> newPassword;

            myClient.channel.sendData("FIRST_LOGIN " + username + " " + tempPassword + " " + newPassword);
            std::string response = myClient.channel.receiveData();

            if (response == "PASS_CHANGED") {
                std::cout << "Password changed successfully. You can now log in with the new password.\n";
                return 0;
            } else {
                std::cerr << "Failed to change password on server, server response : " + response +"\n";
                return 1;
            }
        }



    }
    else {
        std::cerr << "Invalid option selected.\n";
        return 1;
    }

    return 0;
}
