#include "secureChannelServer.h"
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

secureChannelServer::secureChannelServer()
    : ctx(nullptr), ssl(nullptr), server_fd(-1), client_fd(-1) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

secureChannelServer::~secureChannelServer() {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (client_fd != -1) close(client_fd);
    if (server_fd != -1) close(server_fd);
}

bool secureChannelServer::initServerContext(const std::string& cert_path, const std::string& key_path, const std::string& ca_cert_path) {
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        return false;
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load certificate\n";
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load private key\n";
        return false;
    }

    // Check private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match certificate\n";
        return false;
    }

    // Load CA cert for verifying client (optional mutual TLS)
    if (!ca_cert_path.empty()) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_load_verify_locations(ctx, ca_cert_path.c_str(), nullptr) != 1) {
            std::cerr << "Failed to load CA cert\n";
            return false;
        }
    }

    // Enforce strong PFS cipher suites
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    return true;
}

bool secureChannelServer::createServerSocket(int port) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return false;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return false;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return false;
    }

    return true;
}

bool secureChannelServer::bindAndListen(int port) {
    return createServerSocket(port);
}

bool secureChannelServer::acceptClient() {
    sockaddr_in client_addr{};
    socklen_t len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0) {
        perror("accept");
        return false;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL handshake failed\n";
        return false;
    }

    std::cout << "Secure channel established with client\n";
    return true;
}

bool secureChannelServer::sendData(const std::string& data) {
    if (SSL_write(ssl, data.c_str(), data.size()) <= 0) {
        std::cerr << "SSL write failed\n";
        return false;
    }
    return true;
}

std::string secureChannelServer::receiveData() {
    char buffer[4096];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        std::cerr << "SSL read failed\n";
        return "";
    }
    return std::string(buffer, bytes);
}
