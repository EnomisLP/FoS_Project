#include "client.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include "Server/crypto.h"
#include <iostream>

client::client(const std::string& host, int port, crypto& cryptoEngine)
    : host(host), port(port), cryptoEngine(cryptoEngine) {}

bool client::authenticate(const std::string& username, const std::string& password) {
    setUsername(username);
    std::string auth_msg = "AUTH " + username + " " + password;
    channel.sendData(auth_msg);
    std::string response = channel.receiveData();
    return response == "AUTH_OK";
}
std::string client::requestCertificate(const std::string& csrPem)
{
    std::string request = "REQ_CERT " + username + " " + csrPem;
    std::cout << "[SERVER] Sending certificate request: " << request << "\n";
    channel.sendData(request);
    std::string response = channel.receiveData();
    return response;
}
bool client::requestCreateKeys(const std::string& username) {
    // 1) Generate keypair + CSR locally
    auto [csrPem, privKeyPem] = cryptoEngine.createCSR(username);
    if (csrPem.empty() || privKeyPem.empty()) {
        std::cerr << "[Client] Failed to create CSR\n";
        return false;
    }

    // 2) Save private key locally (not shared!)
    std::string userDir = "/home/simon/Secret/" + username;
    std::filesystem::create_directories(userDir);
    std::ofstream privFile(userDir + "/" + username + ".key");
    privFile << privKeyPem;
    privFile.close();

    // 3) Send CSR to DSS
    std::string certPem = requestCertificate(csrPem);
    if (certPem.empty() || certPem == "KEYS_FAILED") {
        std::cerr << "[Client] DSS/CA failed to sign CSR\n";
        return false;
    }

    // 4) Save certificate
    std::ofstream certFile(userDir + "/" + username + ".crt");
    certFile << certPem;
    certFile.close();

    std::cout << "[Client] Certificate received and stored.\n";
    return true;
}


bool client::requestSignDoc(const std::string& document) {
    std::string msg = "SIGN_DOC " + username + " " + document;
    channel.sendData(msg);
    std::string sig = channel.receiveData();
    if (!sig.empty() && sig != "SIGN_FAIL") {
        std::cout << "Signature received (" << sig.size() << " bytes)\n";
        return true;
    }
    return false;
}

std::string client::requestGetPublicKey(const std::string& username) {
    channel.sendData("GET_PUBLIC_KEY " + username);
    return channel.receiveData();
}

void client::requestDeleteKeys(const std::string& username) {
    std::string request = "DEL_KEYS " + username;
    channel.sendData(request);
    std::string response = channel.receiveData();
    if(response == "DEL_OK") {
        std::cout << "[Client] Keys deleted successfully on server.\n";
        std::string userDir = "/home/simon/Secret/" + username;
        std::filesystem::remove_all(userDir);
        std::cout << "[Client] Local keys deleted successfully from " << userDir << ".\n";
    }
    else {
        std::cerr << "[Client] Failed to delete keys, try again later. Server response was: " << response << "\n";
    }
}
