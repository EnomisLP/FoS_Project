#include "secureChannelClient.h"
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>
#include <limits>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <ctime>
#include "DB/db.h"
#include <chrono>
#include <atomic>
#include <thread>

secureChannelClient::secureChannelClient(db &databaseHandle) : ctx(nullptr), ssl(nullptr), server_fd(-1), databaseHandle(databaseHandle) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
}

secureChannelClient::~secureChannelClient() {
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
    if (server_fd != -1) close(server_fd);
    
}

bool secureChannelClient::initClientContext(const std::string& caCertPath, db &databaseHandle) {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "[Client] Failed to create SSL context\n";
        return false;
    }

    // Load the CA certificate that signed the DSS server certificate
    if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) <= 0) {
        std::cerr << "[Client] Failed to load CA certificate: " << caCertPath << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // Strong ciphers
    if (SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        std::cerr << "[Client] Failed to set cipher list\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    this->databaseHandle = databaseHandle;

    return true;
}

std::string secureChannelClient::random_hex(int bytes = 16) {
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
    if (!ssl) {
        std::cerr << "[Client] Failed to create SSL structure\n";
        return false;
    }

    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) != 1) {
        int ssl_error = SSL_get_error(ssl, -1);
        std::cerr << "[Client] SSL handshake failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    std::cout << "[Client] Secure channel established with " << host << "\n";
    return true;
}

bool secureChannelClient::connectToCA(const std::string& host,
                                      int port,
                                      const std::string& caCertPath) {
    // 1. Init client SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "[DSS->CA] Failed to create SSL context\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 2. Load CA certificate (trust anchor)
    if (SSL_CTX_load_verify_locations(ctx, caCertPath.c_str(), nullptr) <= 0) {
        std::cerr << "[DSS->CA] Failed to load CA certificate: " << caCertPath << "\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 3. Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    // 4. Set cipher suites
    if (SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        std::cerr << "[DSS->CA] Failed to set cipher list\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 5. Create TCP connection to CA
    if (!createSocket(host, port)) {
        std::cerr << "[DSS->CA] Failed to connect socket to " << host << ":" << port << "\n";
        return false;
    }

    // 6. Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "[DSS->CA] Failed to create SSL structure\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    SSL_set_fd(ssl, server_fd);

    // 7. Start handshake
    std::cout << "[DSS->CA] Starting TLS handshake with " << host << "...\n";
    int ret = SSL_connect(ssl);
    if (ret != 1) {
        int err = SSL_get_error(ssl, ret);
        std::cerr << "[DSS->CA] SSL_connect failed (error: " << err << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 8. Verify server certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "[DSS->CA] No certificate presented by CA\n";
        return false;
    }

    long verifyResult = SSL_get_verify_result(ssl);
    if (verifyResult != X509_V_OK) {
        std::cerr << "[DSS->CA] Certificate verification failed: "
                  << X509_verify_cert_error_string(verifyResult) << "\n";
        X509_free(cert);
        return false;
    }

    std::cout << "[DSS->CA] Secure channel established with CA at "
              << host << ":" << port << "\n";

    // Optional: log cipher suite
    std::cout << "[DSS->CA] Using " << SSL_get_version(ssl)
              << " with " << SSL_get_cipher(ssl) << "\n";

    X509_free(cert);
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


bool secureChannelClient::authenticateServerWithCertificate(const std::string& trustedCertPath) {
    // Get the server certificate from the TLS session
    X509* serverCert = SSL_get_peer_certificate(ssl);
    if (!serverCert) {
        std::cerr << "[Client] No certificate received from server.\n";
        return false;
    }

    // Load the trusted certificate from file
    FILE* f = fopen(trustedCertPath.c_str(), "r");
    if (!f) {
        std::cerr << "[Client] Failed to open trusted cert file: " << trustedCertPath << "\n";
        X509_free(serverCert);
        return false;
    }
    X509* trustedCert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!trustedCert) {
        std::cerr << "[Client] Failed to parse trusted cert file.\n";
        X509_free(serverCert);
        return false;
    }

    // Compare both certificates
    bool match = (X509_cmp(serverCert, trustedCert) == 0);

    if (match) {
        std::cout << "[Client] DSS certificate verified successfully.\n";
    } else {
        std::cerr << "[Client] DSS certificate mismatch!\n";
    }

    X509_free(serverCert);
    X509_free(trustedCert);

    return match;
}

std::string secureChannelClient::receiveData() {
    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_read);
        if (ssl_error == SSL_ERROR_ZERO_RETURN) {
            std::cout << "[Client] Connection closed cleanly\n";
        } else if (ssl_error == SSL_ERROR_SYSCALL && bytes_read == 0) {
            std::cerr << "[Client] Unexpected EOF from server\n";
        } else {
            std::cerr << "[Client] SSL_read failed (error: " << ssl_error << ")\n";
            ERR_print_errors_fp(stderr);
        }
        return "";
    }

    buffer[bytes_read] = '\0';
    std::cout << "[Client] Received " << bytes_read << " bytes\n";
    return std::string(buffer, bytes_read);
}

// Modified sendData to check for connection state
bool secureChannelClient::sendData(const std::string& data) {
    if (!ssl) {
        std::cerr << "[Client] SSL not initialized\n";
        return false;
    }

    int bytes_written = SSL_write(ssl, data.c_str(), data.length());
    
    if (bytes_written <= 0) {
        int ssl_error = SSL_get_error(ssl, bytes_written);
        std::cerr << "[Client] SSL_write failed (error: " << ssl_error << ")\n";
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    std::cout << "[Client] Sent " << bytes_written << " bytes\n";
    return true;
}

bool secureChannelClient::sendWithClientNonce(const std::string& owner, const std::string& payload, int ttl_seconds = 300) {
    long ts = static_cast<long>(std::time(nullptr));
    std::string nonce = random_hex();

    // Build message: payload + " " + ts + " " + nonce
    std::ostringstream oss;
    oss << payload << " " << ts << " " << nonce;
    std::string msg = oss.str();

    // Store the nonce in DB (owner identifies who is creating the request)
    // Note: if storeNonceIfFresh returns false here, treat as error (shouldn't happen for new nonce)
    if (!databaseHandle.storeClientNonceIfFresh(owner, nonce, ttl_seconds)) {
        std::cerr << "[DSS->CA] Failed to store nonce (possible replay) owner=" << owner << " nonce=" << nonce << "\n";
        return false;
    }

    // send over TLS (use your existing sendData)
    return sendData(msg);
}
std::string secureChannelClient::receiveAndVerifyClientNonce(const std::string& ownerIdentifier) {
    // 1. Receive raw message
    std::string rawMsg = receiveData();
    if (rawMsg.empty()) {
        std::cerr << "[Server] Empty message received\n";
        return "";
    }

    // 2. Parse payload + timestamp + nonce
    auto last_space = rawMsg.find_last_of(' ');
    auto second_last_space = rawMsg.find_last_of(' ', last_space - 1);
    if (last_space == std::string::npos || second_last_space == std::string::npos) {
        std::cerr << "[Server] Malformed message: " << rawMsg << "\n";
        sendData("MALFORMED_REQUEST");
        return "";
    }

    std::string nonce = rawMsg.substr(last_space + 1);
    std::string ts_str = rawMsg.substr(second_last_space + 1, last_space - second_last_space - 1);
    std::string payload = rawMsg.substr(0, second_last_space);

    long ts = 0;
    try { ts = std::stol(ts_str); } 
    catch (...) {
        std::cerr << "[Server] Invalid timestamp: " << ts_str << "\n";
        sendData("INVALID_TIMESTAMP");
        return "";
    }

    // 3. Timestamp freshness check
    const int ALLOWED_SKEW = 300; // seconds
    long now = std::time(nullptr);
    if (std::llabs(now - ts) > ALLOWED_SKEW) {
        std::cerr << "[Server] Timestamp too old/future: " << ts << "\n";
        sendData("ERROR_TS");
        return "";
    }

    // 4. Replay protection
    if (!databaseHandle.storeClientNonceIfFresh(ownerIdentifier, nonce, ALLOWED_SKEW)) {
        std::cerr << "[Server] Replay detected for nonce: " << nonce << "\n";
        sendData("REPLAY_DETECTED");
        return "";
    }

    // 5. All checks passed
    return payload;
}
bool secureChannelClient::sendWithDSSNonce(const std::string& owner, const std::string& payload, int ttl_seconds = 300) {
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
std::string secureChannelClient::receiveAndVerifyDSSNonce(const std::string& ownerIdentifier) {
    // 1. Receive raw message
    std::string rawMsg = receiveData();
    if (rawMsg.empty()) {
        std::cerr << "[Server] Empty message received\n";
        return "";
    }

    // 2. Parse payload + timestamp + nonce
    auto last_space = rawMsg.find_last_of(' ');
    auto second_last_space = rawMsg.find_last_of(' ', last_space - 1);
    if (last_space == std::string::npos || second_last_space == std::string::npos) {
        std::cerr << "[Server] Malformed message: " << rawMsg << "\n";
        sendData("MALFORMED_REQUEST");
        return "";
    }

    std::string nonce = rawMsg.substr(last_space + 1);
    std::string ts_str = rawMsg.substr(second_last_space + 1, last_space - second_last_space - 1);
    std::string payload = rawMsg.substr(0, second_last_space);

    long ts = 0;
    try { ts = std::stol(ts_str); } 
    catch (...) {
        std::cerr << "[Server] Invalid timestamp: " << ts_str << "\n";
        sendData("INVALID_TIMESTAMP");
        return "";
    }

    // 3. Timestamp freshness check
    const int ALLOWED_SKEW = 300; // seconds
    long now = std::time(nullptr);
    if (std::llabs(now - ts) > ALLOWED_SKEW) {
        std::cerr << "[Server] Timestamp too old/future: " << ts << "\n";
        sendData("ERROR_TS");
        return "";
    }

    // 4. Replay protection
    if (!databaseHandle.storeDSSNonceIfFresh(ownerIdentifier, nonce, ALLOWED_SKEW)) {
        std::cerr << "[Server] Replay detected for nonce: " << nonce << "\n";
        sendData("REPLAY_DETECTED");
        return "";
    }

    // 5. All checks passed
    return payload;
}