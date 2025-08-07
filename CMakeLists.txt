cmake_minimum_required(VERSION 3.10)
project(FoS_Project LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB_RECURSE SOURCES
    "${PROJECT_SOURCE_DIR}/DSS/*.cpp"
)

include_directories(
    ${PROJECT_SOURCE_DIR}/DSS
    ${PROJECT_SOURCE_DIR}/DSS/DB
    ${PROJECT_SOURCE_DIR}/DSS/Server
    ${PROJECT_SOURCE_DIR}/DSS/Client
    ${PROJECT_SOURCE_DIR}/DSS/Protocol
    ${PROJECT_SOURCE_DIR}/DSS/Models
    ${PROJECT_SOURCE_DIR}/DSS/Certifications
)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)  

add_executable(fos ${SOURCES})

target_link_libraries(fos
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3  
)
