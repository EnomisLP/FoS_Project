cmake_minimum_required(VERSION 3.10)
project(FoS_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Common include directories
set(COMMON_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/DSS
    ${PROJECT_SOURCE_DIR}/DSS/DB
    ${PROJECT_SOURCE_DIR}/DSS/Server
    ${PROJECT_SOURCE_DIR}/DSS/Client
    ${PROJECT_SOURCE_DIR}/DSS/Protocol
    ${PROJECT_SOURCE_DIR}/DSS/Models
    ${PROJECT_SOURCE_DIR}/DSS/Certifications
    ${PROJECT_SOURCE_DIR}/DSS/CA
    
)

include_directories(${COMMON_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(nlohmann_json REQUIRED)  

# === Server executable ===
add_executable(fos
    ${PROJECT_SOURCE_DIR}/DSS/ServerMain.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Server/dssServer.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Server/crypto.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelServer.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelCA.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelClient.cpp
    ${PROJECT_SOURCE_DIR}/DSS/DB/db.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/CA.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/caServer.cpp
)

target_link_libraries(fos
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    nlohmann_json::nlohmann_json
)

# === Client executable ===
add_executable(client_app
    ${PROJECT_SOURCE_DIR}/DSS/ClientMain.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Client/client.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelClient.cpp
    ${PROJECT_SOURCE_DIR}/DSS/DB/db.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Server/crypto.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/CA.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/caServer.cpp
)

target_link_libraries(client_app
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    nlohmann_json::nlohmann_json
)

# === CA executable ===
add_executable(ca
    ${PROJECT_SOURCE_DIR}/DSS/CAMain.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelClient.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelServer.cpp
    ${PROJECT_SOURCE_DIR}/DSS/Protocol/secureChannelCA.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/CA.cpp
    ${PROJECT_SOURCE_DIR}/DSS/CA/caServer.cpp

)

target_link_libraries(ca
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    nlohmann_json::nlohmann_json
)

