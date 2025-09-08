#include "secureChannelCA.h"
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

secureChannelCA::secureChannelCA() : ctx(nullptr), ssl(nullptr), server_fd(-1), client_fd(-1) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

secureChannelCA::~secureChannelCA() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (client_fd >= 0) close(client_fd);
    if (server_fd >= 0) close(server_fd);
    if (ctx) SSL_CTX_free(ctx);
}

bool secureChannelCA::initCAContext(const std::string& caCertPath,
                                    const std::string& serverKeyPath,
                                    const std::string& serverCertPath) {
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "[CA Server] Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Load CA server certificate & private key
    if (SSL_CTX_use_certificate_file(ctx, serverCertPath.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, serverKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[CA Server] Failed to load server cert or key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[CA Server] Private key does not match certificate\n";
        return false;
    }

    // Load root CA for verifying DSS client (optional, you can skip for one-way TLS)
    if (!caCertPath.empty()) {
        if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) != 1) {
            std::cerr << "[CA Server] Failed to load CA certificate\n";
            ERR_print_errors_fp(stderr);
            return false;
        }
        // Only require client cert if you implement mutual TLS
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

    std::cout << "[CA Server] SSL context initialized\n";
    return true;
}


bool secureChannelCA::createSocket(int port) {
    // Create TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[CA Server] socket");
        return false;
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[CA Server] setsockopt");
        close(server_fd);
        server_fd = -1;
        return false;
    }

    // Bind socket
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[CA Server] bind");
        close(server_fd);
        server_fd = -1;
        return false;
    }

    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("[CA Server] listen");
        close(server_fd);
        server_fd = -1;
        return false;
    }

    return true;
}

bool secureChannelCA::bindAndListen(int port) {
    return createSocket(port);
}

bool secureChannelCA::acceptConnection() {
    if (server_fd < 0) {
        std::cerr << "[CA Server] Server socket not initialized\n";
        return false;
    }

    sockaddr_in client_addr{};
    socklen_t len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0) {
        perror("[CA Server] accept");
        return false;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::cout << "[CA Server] Connection accepted from " << client_ip
              << ":" << ntohs(client_addr.sin_port) << "\n";

    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[CA Server] Failed to create SSL structure\n";
        ERR_print_errors_fp(stderr);
        close(client_fd);
        client_fd = -1;
        return false;
    }

    SSL_set_fd(ssl, client_fd);

    int ssl_result = SSL_accept(ssl);
    if (ssl_result <= 0) {
        int ssl_error = SSL_get_error(ssl, ssl_result);
        std::cerr << "[CA Server] SSL handshake failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        close(client_fd);
        client_fd = -1;
        return false;
    }

    std::cout << "[CA Server] Secure channel established with DSS\n";
    return true;
}

 SSL* secureChannelCA::getSSL() const {
    return ssl;
}
std::string secureChannelCA::getServerPublicKey() {
    if (!ssl) {
        std::cerr << "[CA Server] SSL connection not established\n";
        return "";
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "[CA Server] No certificate received from peer\n";
        return "";
    }

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        std::cerr << "[CA Server] Failed to extract public key from certificate\n";
        X509_free(cert);
        return "";
    }

    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem) {
        std::cerr << "[CA Server] Failed to create BIO\n";
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return "";
    }

    if (PEM_write_bio_PUBKEY(mem, pkey) != 1) {
        std::cerr << "[CA Server] Failed to write public key to BIO\n";
        BIO_free(mem);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return "";
    }

    char* data;
    long len = BIO_get_mem_data(mem, &data);
    std::string pubkey(data, len);

    BIO_free(mem);
    EVP_PKEY_free(pkey);
    X509_free(cert);

    return pubkey;
}

bool secureChannelCA::authenticateCAWithCertificate(const std::string& trustedCertPath) {
    if (!ssl) {
        std::cerr << "[CA Server] SSL connection not established\n";
        return false;
    }

    // Get the client certificate from the TLS session
    X509* client_cert = SSL_get_peer_certificate(ssl);
    if (!client_cert) {
        std::cerr << "[CA Server] No certificate received from client\n";
        return false;
    }

    // Load the trusted certificate from file
    FILE* f = fopen(trustedCertPath.c_str(), "r");
    if (!f) {
        std::cerr << "[CA Server] Failed to open trusted cert file: " << trustedCertPath << "\n";
        X509_free(client_cert);
        return false;
    }
    
    X509* trusted_cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    
    if (!trusted_cert) {
        std::cerr << "[CA Server] Failed to parse trusted cert file\n";
        ERR_print_errors_fp(stderr);
        X509_free(client_cert);
        return false;
    }

    // Compare both certificates
    bool match = (X509_cmp(client_cert, trusted_cert) == 0);

    if (match) {
        std::cout << "[CA Server] DSS certificate verified successfully\n";
    } else {
        std::cerr << "[CA Server] DSS certificate mismatch!\n";
    }

    X509_free(client_cert);
    X509_free(trusted_cert);

    return match;
}

bool secureChannelCA::sendData(const std::string& data) {
    int bytes_written = SSL_write(ssl, data.c_str(), data.size());
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        std::cerr << "[CA Server] SSL_write failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (bytes_written != static_cast<int>(data.size())) {
        std::cerr << "[CA Server] Partial write: " << bytes_written
                  << "/" << data.size() << " bytes\n";
        return false;
    }

    return true;
}

std::string secureChannelCA::receiveData() {
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            std::cout << "[CA Server] Connection closed by client\n";
        } else {
            std::cerr << "[CA Server] SSL_read failed (error: " << ssl_error << ")\n";
            ERR_print_errors_fp(stderr);
        }
        return "";
    }

    buffer[bytes_read] = '\0';
    return std::string(buffer, bytes_read);
}
