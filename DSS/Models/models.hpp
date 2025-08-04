#pragma once
#include <string>
#include <optional>

struct User {
    int id;
    std::string username;
    std::string password_hash;
    bool first_login;
};

struct KeyPair {
    int user_id;
    std::string public_key;
    std::string encrypted_private_key;
    std::string created_at;
};

struct SignedDocument {
    std::string original_document;
    std::string signature;
};

struct AuthenticationRequest {
    std::string username;
    std::string password_hash;
};

enum class OperationType {
    CreateKeys,
    SignDoc,
    GetPublicKey,
    DeleteKeys
};

struct DSSRequest {
    OperationType type;
    std::string payload;
};

struct DSSResponse {
    bool success;
    std::string message;
    std::optional<std::string> data;
};
