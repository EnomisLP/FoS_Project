#pragma once
#include <string>

class crypto {
public:
    // Constructor
    crypto();

    // Methods
    std::string createCSR(const std::string& username,
                               const std::string& pubPem,
                               const std::string& privPem);
    static std::string hash_password(const std::string& password);
    bool verifyCertificate(const std::string& certPem, const std::string& caPath);
    std::pair<std::string, std::string> generateKeypair();
    std::string extractPublicKey(const std::string& certPem);
    std::string signFile(const std::string& privKeyPem, const std::string& filePath);
    std::string encrypt_private_key(const std::string& priv_key, const std::string& password);
    std::string decrypt_private_key(const std::string& encrypted, const std::string& password);
};
