#include "secureChannelServer.h"
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <random>
#include <sstream>
#include <iomanip>
#include <limits>
#include <ctime>
#include "DB/db.h"
#include <atomic>
#include <thread>
#include <chrono>

secureChannelServer::secureChannelServer(db &databaseHandle)
    : ctx(nullptr), ssl(nullptr), server_fd(-1), client_fd(-1), databaseHandle(databaseHandle) {
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

bool secureChannelServer::initServerContext(const std::string& certPath,
                                            const std::string& keyPath,
                                            const std::string& caCertPath,
                                            db &databaseHandle) {
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "[DSS Server] Failed to create SSL context\n";
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "[DSS Server] Failed to load cert/key\n";
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "[DSS Server] Private key does not match certificate\n";
        return false;
    }

    // Optional: verify client (users don’t have certs, so we skip)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

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
    if (server_fd < 0) {
        std::cerr << "[DSS Server] Server socket not initialized\n";
        return false;
    }

    sockaddr_in client_addr{};
    socklen_t len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0) {
        perror("[DSS Server] accept");
        return false;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[DSS Server] Failed to create SSL structure\n";
        close(client_fd);
        client_fd = -1;
        return false;
    }

    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        int ssl_error = SSL_get_error(ssl, -1);
        std::cerr << "[DSS Server] SSL handshake failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        ssl = nullptr;
        close(client_fd);
        client_fd = -1;
        return false;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::cout << "[DSS Server] Secure channel established with client " 
              << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";
    

    return true;
}

std::string secureChannelServer::random_hex(int bytes = 16) {
    // Use a static counter to ensure uniqueness even if called rapidly
    static std::atomic<uint64_t> counter{0};
    
    std::random_device rd;
    std::mt19937_64 gen;
    
    // Seed with multiple entropy sources
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = now.time_since_epoch().count();
    auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
    auto process_id = getpid();
    auto counter_val = counter.fetch_add(1);
    
    // Combine all entropy sources
    gen.seed(rd() ^ timestamp ^ thread_id ^ process_id ^ counter_val);
    
    std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    
    // Include timestamp and counter in the nonce for guaranteed uniqueness
    ss << std::setw(16) << timestamp;
    ss << std::setw(8) << counter_val;
    
    // Add random bytes
    int remaining_bytes = bytes - 12; // We already used 12 bytes (8 for timestamp, 4 for counter)
    if (remaining_bytes > 0) {
        int chunks = remaining_bytes / 8;
        int rem = remaining_bytes % 8;
        
        for (int i = 0; i < chunks; ++i) {
            uint64_t v = dist(gen);
            ss << std::setw(16) << v;
        }
        if (rem > 0) {
            uint64_t v = dist(gen);
            std::string s;
            {
                std::ostringstream tmp;
                tmp << std::hex << std::setfill('0') << std::setw(16) << v;
                s = tmp.str();
            }
            ss << s.substr(0, rem * 2);
        }
    }
    
    std::string result = ss.str();
    std::cout << "[DEBUG] Generated unique nonce: " << result << " (length: " << result.length() << ")\n";
    return result;
}

std::string secureChannelServer::receiveData() {
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            std::cout << "[DSS] Connection closed cleanly\n";
        } else if (ssl_error == SSL_ERROR_SYSCALL && bytes_read == 0) {
            std::cerr << "[DSS] Unexpected EOF from server\n";
        } else {
            std::cerr << "[DSS] SSL_read failed (error: " << ssl_error << ")\n";
            ERR_print_errors_fp(stderr);
        }
        return "";
    }

    buffer[bytes_read] = '\0';
    std::cout << "[DSS] Received " << bytes_read << " bytes\n";
    return std::string(buffer, bytes_read);
}

// Modified sendData to check for connection state
bool secureChannelServer::sendData(const std::string& data) {
    if (!ssl) {
        std::cerr << "[DSS] SSL not initialized\n";
        return false;
    }

    int bytes_written = SSL_write(ssl, data.c_str(), data.length());
    
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        std::cerr << "[DSS] SSL_write failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "[DSS] Sent " << bytes_written << " bytes\n";
    return true;
}


bool secureChannelServer::sendWithDSSNonce(const std::string& owner, const std::string& payload, int ttl_seconds = 300) {
    long ts = static_cast<long>(std::time(nullptr));
    std::string nonce = random_hex();

    // Build message: payload + " " + ts + " " + nonce
    std::ostringstream oss;
    oss << payload << " " << ts << " " << nonce;
    std::string msg = oss.str();

    // Store the nonce in DB (owner identifies who is creating the request)
    // Note: if storeNonceIfFresh returns false here, treat as error (shouldn't happen for new nonce)
    if (!databaseHandle.storeDSSNonceIfFresh(owner, nonce, ttl_seconds)) {
        std::cerr << "[DSS->CA] Failed to store nonce (possible replay) owner=" << owner << " nonce=" << nonce << "\n";
        return false;
    }

    // send over TLS (use your existing sendData)
    return sendData(msg);
}
