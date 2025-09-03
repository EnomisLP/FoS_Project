#include "secureChannelCA.h"
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

secureChannelCA::secureChannelCA() : ctx(nullptr), ssl(nullptr), server_fd(-1) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

secureChannelCA::~secureChannelCA() {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (server_fd != -1) close(server_fd);
}

bool secureChannelCA::initCAContext(const std::string& caCertPath,
                                    const std::string& clientKeyPath,
                                    const std::string& clientCertPath) {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context\n";
        return false;
    }

    if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) <= 0) {
        std::cerr << "Failed to load CA certificate\n";
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx, clientCertPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load DSS certificate\n";
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, clientKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load DSS key\n";
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "DSS private key does not match certificate\n";
        return false;
    }

    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    return true;
}


bool secureChannelCA::createSocket(const std::string& host, int port) {
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
bool secureChannelCA::bindAndListen(const std::string& host, int port) {
    return createSocket(host, port);
}
bool secureChannelCA::acceptConnection() {
    sockaddr_in client_addr{};
    socklen_t len = sizeof(client_addr);

    server_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (server_fd < 0) {
        perror("accept");
        return false;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL handshake failed\n";
        return false;
    }

    std::cout << "Secure channel established with DSS\n";
    return true;
}
bool secureChannelCA::connectToCA(const std::string& host, int port, 
                                  const std::string& caCertPath,
                                  const std::string& clientKeyPath,
                                  const std::string& clientCertPath) {
    // Create TCP socket and connect
    if (!createSocket(host, port)) {
        std::cerr << "[CAClient] Failed to connect socket to " << host << ":" << port << "\n";
        return false;
    }

    // Load DSS client certificate
    if (SSL_CTX_use_certificate_file(ctx, clientCertPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[CAClient] Failed to load client certificate: " << clientCertPath << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Load DSS client private key
    if (SSL_CTX_use_PrivateKey_file(ctx, clientKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[CAClient] Failed to load client private key: " << clientKeyPath << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Verify client cert/key pair
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[CAClient] Client private key does not match the certificate\n";
        return false;
    }

    // Load trusted CA certificate(s)
    if (!SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr)) {
        std::cerr << "[CAClient] Failed to load CA certificate: " << caCertPath << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Create SSL session and bind to socket
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) != 1) {
        std::cerr << "[CAClient] SSL handshake failed with " << host << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Verify CA’s certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "[CAClient] No certificate presented by CA\n";
        return false;
    }
    X509_free(cert);

    long verifyResult = SSL_get_verify_result(ssl);
    if (verifyResult != X509_V_OK) {
        std::cerr << "[CAClient] Certificate verification failed: "
                  << X509_verify_cert_error_string(verifyResult) << "\n";
        return false;
    }

    std::cout << "[CAClient] Secure channel established with CA at " << host << ":" << port << "\n";
    return true;
}


std::string secureChannelCA::getServerPublicKey() {
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


bool secureChannelCA::authenticateCAWithCertificate(const std::string& trustedCertPath) {
    // Get the server certificate from the TLS session
    X509* serverCert = SSL_get_peer_certificate(ssl);
    if (!serverCert) {
        std::cerr << "[Server] No certificate received from server.\n";
        return false;
    }

    // Load the trusted certificate from file
    FILE* f = fopen(trustedCertPath.c_str(), "r");
    if (!f) {
        std::cerr << "[Server] Failed to open trusted cert file: " << trustedCertPath << "\n";
        X509_free(serverCert);
        return false;
    }
    X509* trustedCert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!trustedCert) {
        std::cerr << "[Server] Failed to parse trusted cert file.\n";
        X509_free(serverCert);
        return false;
    }

    // Compare both certificates
    bool match = (X509_cmp(serverCert, trustedCert) == 0);

    if (match) {
        std::cout << "[Server] DSS certificate verified successfully.\n";
    } else {
        std::cerr << "[Server] DSS certificate mismatch!\n";
    }

    X509_free(serverCert);
    X509_free(trustedCert);

    return match;
}

bool secureChannelCA::sendData(const std::string& data) {
    int ret = SSL_write(ssl, data.c_str(), data.size());
    if (ret <= 0) {
        std::cerr << "[Server] SSL_write failed\n";
        return false;
    }
    return true;
}
std::string secureChannelCA::receiveData() {
    char buffer[4096];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes <= 0) {
        std::cerr << "SSL read failed\n";
        return "";
    }
    return std::string(buffer, bytes);
}
