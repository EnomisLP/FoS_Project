#pragma once
#include "Protocol/secureChannelCA.h"
#include "CA.h"
#include "DB/dbCA.h"
#include <string>

class caServer {
public:
    explicit caServer(CA& caInstance, dbCA& dbInstance);

    std::string handleRequestCertificate(int user_id, const std::string& csrPem);
    bool handleRevokeCertificate(int user_id, const std::string& serial);

    inline std::string getCurrentTime();
    inline std::string getExpiryTime(int days);

private:
    CA& ca;  // store as reference
    dbCA& db; // CA's own database instance

};
