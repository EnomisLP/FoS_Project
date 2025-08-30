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
void runClientMenuUser(client& myClient) {
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
void runClientMenuAdmin(client& myClient) {
    int choice;
    do {
        std::cout << "\n=== Client Menu ADMIN ===\n";
        std::cout << "1. Create Keys\n";
        std::cout << "2. Sign Document\n";
        std::cout << "3. Get Public Key\n";
        std::cout << "4. Delete Keys\n";
        std::cout << "5. Register User\n";
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
            case 5: {
                std::cin.ignore();
                std::string newUsername;
                std::cout << "Enter new username to register: ";
                std::getline(std::cin, newUsername);
                std::string tempPassword = generateRandomPassword();
                myClient.channel.sendData("REGISTER_USER" + newUsername + " " + tempPassword);
                std::string response = myClient.channel.receiveData();
                if (response == "USER_REGISTERED") {
                    std::cout << "[Server Response] User registered successfully.\n";
                } else {
                    std::cout << "[Server Response] " << response << "\n";
                }
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
    secureChannelClient channel;
    if (!channel.initClientContext()) {
        std::cerr << "Failed to initialize SSL context\n";
        return 1;
    }
    std::cout << "[CLIENT] Fetching the DSS public key stored into the device...\n";

    if (!channel.connectToServer("localhost", 5555)) {
        std::cerr << "Failed to connect to server\n";
        return 1;
    }

    // Authenticate DSS server against the trusted offline cert
    if (!channel.authenticateServerWithCertificate("/home/simon/Projects/FoS_Project/DSS/Client/server.crt")) {
    std::cerr << "[Client] Server authentication failed.\n";
    return 1;
    }

    std::cout << "[Client] Server authenticated. You can now login.\n";

    int loginOption;
    std::cout << "Select login type:\n1. Normal login\n2. First login with temporary password\n3. Exit\n";
    std::cin >> loginOption;

    client myClient("localhost", 5555);
    myClient.setChannel(channel);

    if (loginOption == 1) {
        std::string username, password;
        std::cout << "Enter username: ";
        std::cin >> username;
        myClient.setUsername(username);

        std::cout << "Enter password: ";
        std::cin >> password;

    // Send login request
        myClient.channel.sendData("AUTH " + username + " " + password);
        std::string response = myClient.channel.receiveData();
    
        if (response == "AUTH_FAIL") {
            std::cerr << "Authentication failed\n";
            return 1;
        } 
        else if (response == "AUTH_ADMIN") {
            std::cout << "[CLIENT] Admin authenticated successfully.\n";
            runClientMenuAdmin(myClient);
        } else if (response == "AUTH_OK") {
            std::cout << "[CLIENT] Authenticated successfully.\n";
            runClientMenuUser(myClient);
        } else if (response == "FIRST_LOGIN") {
        std::cout << "[CLIENT] First login detected. Please log in with option 2.\n";
        return 1;
        }
    }
        else if (loginOption == 2) {
        std::string username, tempPassword, newPassword;
        std::cout << "Enter username: ";
        std::cin >> username;
        myClient.setUsername(username);

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
            return 1;
        }
    } 
    else if (loginOption == 3) {
        std::cout << "Exiting client...\n";
        return 0;
    } 
    else {
        std::cout << "Invalid option. Try again.\n";
        return 1;
    }

    return 0;
}
