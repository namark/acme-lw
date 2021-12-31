#ifndef VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_H
#define VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_H

#include "acme-lw.h"


namespace acme_lw
{


struct ZeroSSLRestAPI {
    static const std::string URL;
    static const std::string CERT_ENDPOINT;
    static const std::string CHALLENGES;
    static const std::string STATUS;
    static const std::string DOWNLOAD;
};

class ZeroSSLClient
{
public:
    ZeroSSLClient(std::string apiKey);
    std::string addAccessKey(std::string url) const;

private:
    std::string apiKey;
};


//TODO: document/specify callback parameters
// maybe also define callback class interface to restore interface/implementation division
/**
    The signingKey is the Acme account private key used to sign
    requests to the acme CA, in pem format.
*/
template <typename Callback>
void init(Callback, std::string apiKey, ZeroSSLRestAPI);

template <typename Callback>
void createAccount(Callback, ZeroSSLClient);

template <typename Callback>
void orderCertificate(Callback, ZeroSSLClient, std::vector<identifier>);

struct ZeroSSLOrderInfo {
    std::string certId;
    std::string csrKey;
    std::vector<identifier> identifiers;
    std::vector<Challenge> challenges;
};

template <typename Callback>
void retrieveCertificate(Callback, ZeroSSLClient, ZeroSSLOrderInfo);

}

#endif /* end of include guard */
