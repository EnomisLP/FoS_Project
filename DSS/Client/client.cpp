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
    return response == "AUTH_OK";

}

bool client::requestCreateKeys() {
    std::string msg = "CREATE_KEYS " + username;
    channel.sendData(msg);
    std::string resp = channel.receiveData();
    return resp == "KEYS_CREATED";
}


bool client::requestSignDoc(const std::string& document) {
    std::string msg = "SIGN_DOC " + username + " " + document;
    channel.sendData(msg);
    std::string sig = channel.receiveData();
    if (!sig.empty() && sig != "SIGN_FAIL") {
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
    return channel.receiveData() == "KEYS_DELETED";
}
