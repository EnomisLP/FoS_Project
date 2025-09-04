#pragma once
#include "Protocol/secureChannelCA.h"
#include "CA.h"
#include <string>

class caServer {
public:
    explicit caServer(CA& caInstance);
    std::string handleRequestCertificate(const std::string& csrPem);
    bool handleRevokeCertificate(const std::string& serial);
private:
    CA& ca;  // store as reference
};
