#pragma once
#include <string>

class crypto {
public:
    // Constructor
    crypto();

    // Methods
    std::pair<std::string, std::string> CreateKeys(const std::string& password);
    std::string SignDoc(const std::string& encrypted_priv_key, const std::string& password, const std::string& document);
    std::string GetPublicKey(const std::string& username);
    static std::string hash_password(const std::string& password);

private:
    std::string encrypt_private_key(const std::string& priv_key, const std::string& password);
    std::string decrypt_private_key(const std::string& encrypted, const std::string& password);
};
