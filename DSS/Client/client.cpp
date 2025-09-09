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

bool client::requestCreateKeys(const std::string& username, const std::string& password) {
    // Just send a request to DSS
    std::string request = "CREATE_KEYS " + username + " " + password;
    channel.sendData(request);

    // Receive the certificate or serial from DSS
    std::string response = channel.receiveData();
    if (response.empty() || response == "KEYS_FAILED") {
        std::cerr << "[Client] DSS failed to create keys for " << username << "\n";
        return false;
    }

    std::cout << "[Client] Keys created successfully for " << username << "\n";
    return true;
}

void client::requestSignDoc(const std::string& username, const std::string& password, const std::string& path) {
    std::string msg = "SIGN_DOC " + username + " " + password + " " + path;
    channel.sendData(msg);
    std::string sig = channel.receiveData();
    std::cout << "[Client] Server response: " << sig << "\n";
    if(sig == "SIGN_OK") {
        std::cout << "[Client] Document signed successfully and stored at same path with .sig extension.\n";
    } else {
        std::cout << "[Client] Document signing failed.\n";
    }
}

std::string client::requestGetCertificate(const std::string& username) {
    channel.sendData("GET_CERTIFICATE " + username);
    std::string response = channel.receiveData();
    
    if (response == "NO_CERT" || response.empty()) {
        std::cerr << "[Client] No certificate found for " << username << "\n";
        return response;
    }

    // Validate the received certificate
    if (!cryptoEngine.verifyCertificate(response)) {
        std::cerr << "[Client] Invalid certificate for " << username << "\n";
        return "INVALID_CERT";
    }

    std::cout << "[Client] Valid certificate received for " << username << "\n";
    std::cout << "[Client] Extracting public key...\n";
    std::string pubKeyPem = cryptoEngine.extractPublicKey(response);
    if (pubKeyPem.empty()) {
        std::cerr << "[Client] Failed to extract public key from certificate.\n";
        return response;
    }
    std::cout << "[Client] Public key extracted successfully:\n" << pubKeyPem << "\n";
    return "[Client] Certificate :\n" + response + "\n";
}

std::string client::requestDeleteCertificate(const std::string& username) {
    std::string request = "DELETE_KEYS " + username; // command to DSS
    channel.sendData(request);
    return channel.receiveData();

}
