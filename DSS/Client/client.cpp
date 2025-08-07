#include "client.h"
#include <iostream>

client::client(const std::string& host, int port, const std::string& ca_cert_path)
    : host(host), port(port), ca_cert_path(ca_cert_path) {}

bool client::connectToServer() {
    if (!channel.initClientContext(ca_cert_path)) return false;
    return channel.connectToServer(host, port);
}

bool client::authenticate(const std::string& username, const std::string& password) {
    this->username = username;
    std::string auth_msg = "AUTH " + username + " " + password;
    channel.sendData(auth_msg);
    std::string response = channel.receiveData();
    return response == "OK";
}

bool client::requestCreateKeys() {
    channel.sendData("CREATE_KEYS");
    std::string resp = channel.receiveData();
    return resp == "OK";
}

bool client::requestSignDoc(const std::string& document) {
    channel.sendData("SIGN_DOC " + document);
    std::string sig = channel.receiveData();
    if (!sig.empty()) {
        std::cout << "Signature received (" << sig.size() << " bytes)\n";
        return true;
    }
    return false;
}

std::string client::requestGetPublicKey(const std::string& username) {
    channel.sendData("GET_PUBLIC_KEY " + username);
    return channel.receiveData();
}

bool client::requestDeleteKeys() {
    channel.sendData("DELETE_KEYS");
    return channel.receiveData() == "OK";
}
