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
    for (int i = 0; i < length; ++i) pass += chars[dis(gen)];
    return pass;
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
                myClient.channel.sendData("CREATE_KEYS " + myClient.getUsername());
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response] " << response << "\n";
                break;
            }
            case 2: {
                std::cin.ignore();
                std::string document;
                std::cout << "Enter document to sign: ";
                std::getline(std::cin, document);

                myClient.channel.sendData("SIGN_DOC " + myClient.getUsername() + " " + document);
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
                myClient.channel.sendData("DELETE_KEYS " + myClient.getUsername());
                std::string response = myClient.channel.receiveData();
                std::cout << "[Server Response] " << response << "\n";
                break;
            }
            case 0:
                std::cout << "Exiting menu...\n";
                break;
            default:
                std::cout << "Invalid option. Try again.\n";
        }
    } while (choice != 0);
}

// ---------------- Main ----------------
int main() {
    std::cout << "[CLIENT] Starting client...\n";

    const std::string offlineFile = "/home/simon/Projects/FoS_Project/DSS/DB/offline_users.json";

    while (true) {
        std::cout << "[CLIENT] Select mode:\n";
        std::cout << "1. Offline registration\n";
        std::cout << "2. Connect to server\n";
        std::cout << "3. Exit\n";
        int option;
        std::cin >> option;
        std::cin.ignore(); // consume newline

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
                continue;
            }

            std::string tempPassword = generateRandomPassword();
            std::string serverPubKey;
            std::cout << "Paste server public key (end with empty line):\n";
            std::string line;
            std::cin.ignore();
            while (std::getline(std::cin, line)) {
                if (line.empty()) break;
                serverPubKey += line + "\n";
            }

            offlineUsers[username] = {
                {"temp_password", tempPassword},
                {"server_pubkey", serverPubKey}
            };

            std::ofstream outFile(offlineFile);
            if (!outFile.is_open()) {
                std::cerr << "Failed to write offline_users.json\n";
                continue;
            }
            outFile << offlineUsers.dump(4);
            outFile.close();

            std::cout << "[CLIENT] Offline registration completed.\n";
            std::cout << "Username: " << username << "\n";
            std::cout << "Temporary password: " << tempPassword << "\n";
            continue;
        }
        else if (option == 2) {
            secureChannelClient channel;
            if (!channel.initClientContext()) {
                std::cerr << "Failed to initialize SSL context\n";
                continue;
            }
            if (!channel.connectToServer("localhost", 5555)) {
                std::cerr << "Failed to connect to server\n";
                continue;
            }

            std::string server_pubkey_input;
            std::cout << "Enter server public key for authentication (end with empty line):\n";
            std::string line;
            while (std::getline(std::cin, line)) {
                if (line.empty()) break;
                server_pubkey_input += line + "\n";
            }

            if (!channel.authenticateServerWithPublicKey(server_pubkey_input)) {
                std::cerr << "[Client] Server authentication failed.\n";
                continue;
            }

            std::cout << "[Client] Server authenticated. You can now login.\n";

            int loginOption;
            std::cout << "Select login type:\n1. Normal login\n2. First login with temporary password\n";
            std::cin >> loginOption;

            client myClient("localhost", 5555);
            myClient.setChannel(channel);

            if (loginOption == 1) {
                std::cout << "Enter username: ";
                std::string username;
                std::cin >> username;
                myClient.setUsername(username);

                std::string password;
                std::cout << "Enter password: ";
                std::cin >> password;

                if (!myClient.authenticate(username, password)) {
                    std::cerr << "Authentication failed\n";
                    continue;
                }
                std::cout << "[CLIENT] Authenticated successfully.\n";
                runClientMenu(myClient);
            }
            else if (loginOption == 2) {
                std::cout << "Enter username: ";
                std::string username;
                std::cin >> username;
                myClient.setUsername(username);

                std::string tempPassword, newPassword;
                std::cout << "Enter temporary password: ";
                std::cin >> tempPassword;
                std::cout << "Enter new password: ";
                std::cin >> newPassword;

                myClient.channel.sendData("FIRST_LOGIN " + username + " " + tempPassword + " " + newPassword);
                std::string response = myClient.channel.receiveData();
                if (response == "PASS_CHANGED") {
                    std::cout << "Password changed successfully. You can now log in with the new password.\n";
                } else {
                    std::cerr << "Failed to change password, server response: " << response << "\n";
                }
            }
            continue;
        }
        else if (option == 3) {
            std::cout << "Exiting...\n";
            break;
        }
        else {
            std::cerr << "Invalid option selected. Try again.\n";
            continue;
        }
    }
    return 0;
}
