#pragma once
#include "Protocol/secureChannelCA.h"
#include "CA.h"
#include <string>

class caServer {
public:
    explicit caServer(CA& caInstance);
    std::string handleRequestCertificate(const std::string& csrPem);

private:
    CA& ca;  // store as reference
};
