#include "secureChannelClient.h"
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

secureChannelClient::secureChannelClient() : ctx(nullptr), ssl(nullptr), server_fd(-1) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

secureChannelClient::~secureChannelClient() {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (server_fd != -1) close(server_fd);
}

bool secureChannelClient::initClientContext(const std::string& ca_cert_path) {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        return false;
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_load_verify_locations(ctx, ca_cert_path.c_str(), nullptr) != 1) {
        std::cerr << "Failed to load CA cert\n";
        return false;
    }

    // Enforce strong cipher suites with PFS
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    return true;
}

bool secureChannelClient::createSocket(const std::string& host, int port) {
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) {
        std::cerr << "No such host\n";
        return false;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return false;
    }

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(server_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        return false;
    }

    return true;
}

bool secureChannelClient::connectToServer(const std::string& host, int port) {
    if (!createSocket(host, port)) return false;

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) != 1) {
        std::cerr << "SSL connection failed\n";
        return false;
    }

    std::cout << "Secure channel established with " << host << "\n";
    return true;
}

bool secureChannelClient::sendData(const std::string& data) {
    if (SSL_write(ssl, data.c_str(), data.size()) <= 0) {
        std::cerr << "SSL write failed\n";
        return false;
    }
    return true;
}

std::string secureChannelClient::receiveData() {
    char buffer[4096];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        std::cerr << "SSL read failed\n";
        return "";
    }
    return std::string(buffer, bytes);
}
