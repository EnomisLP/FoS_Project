#include "secureChannelClient.h"
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>

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

bool secureChannelClient::initClientContext() {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        return false;
    }

    // Do not require system CA verification; we will verify manually
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    return true;
}

bool secureChannelClient::createSocket(const std::string& host, int port) {
    struct hostent* server = gethostbyname(host.c_str());
    if (!server) { std::cerr << "No such host\n"; return false; }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return false; }

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

    std::cout << "[Client] Secure channel established with " << host << "\n";
    return true;
}

std::string secureChannelClient::getServerPublicKey() {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return "";

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(mem, pkey);
    char* data;
    long len = BIO_get_mem_data(mem, &data);
    std::string pubkey(data, len);

    EVP_PKEY_free(pkey);
    BIO_free(mem);
    X509_free(cert);

    return pubkey;
}


bool secureChannelClient::authenticateServerWithPublicKey(const std::string& expected_pubkey_pem) {
    std::string server_pubkey = getServerPublicKey();
    if (server_pubkey.empty()) return false;

    if (server_pubkey == expected_pubkey_pem) {
        std::cout << "[Client] Server public key verified successfully.\n";
        return true;
    } else {
        std::cerr << "[Client] Server public key mismatch!\n";
        return false;
    }
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
