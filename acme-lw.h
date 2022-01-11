#ifndef VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ACME_LW_H
#define VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ACME_LW_H

#include "acme-exception.h"

#include <ctime>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace acme_lw
{

template <typename T>
struct ExpiryResult {
    bool success;
    T value;
    AcmeException error;
};

using ExpiryTimepointResult = ExpiryResult<std::chrono::system_clock::time_point>;

struct Certificate
{
    std::string fullchain;
    std::string privkey;

    // Note that neither of the 'Expiry' calls below require 'privkey'
    // to be set; they only rely on 'fullchain'.

    /**
        Returns the number of seconds since 1970, i.e., epoch time.

        Due to openssl quirkiness on older versions (< 1.1.1?) there
        might be a little drift from a strictly accurate result, but
        it will be close enough for the purpose of determining
        whether the certificate needs to be renewed.
    */
    std::chrono::system_clock::time_point getExpiry() const;
    ExpiryTimepointResult getExpiryOrError() const;

    /**
        Returns the 'Not After' result that openssl would display if
        running the following command.

            openssl x509 -noout -in fullchain.pem -text

        For example:

            May  6 21:15:03 2018 GMT
    */
    std::string getExpiryDisplay() const;
};

struct AcmeClientImpl;

class AcmeClient
{
public:
    AcmeClient(
            std::string privateKey,
            std::string newAccountUrl,
            std::string newOrderUrl,
            std::string newNonceUrl,
            std::string eab_kid = "",
            std::string eab_hmac = "");


    std::unique_ptr<AcmeClientImpl> impl_;
};

struct identifier {
    enum class type { ip, domain };
    std::string name;
    enum type type;
};

std::string toString(enum identifier::type t);

// TODO: document/specify callback parameters,
// maybe also define callback class interface to restore
// interface/implementation division
//
// TODO: callback should be the last argument,
// defaulted arguments could be replaced by overloads, if necessary
/**
    The signingKey is the Acme account private key used to sign
    requests to the acme CA, in pem format.
*/
template <typename Callback>
void init(Callback, std::string signingKey,
    std::string directoryUrl,
	std::string eab_kid = "", std::string eab_hmac = "");

template <typename Callback>
void sendRequest(Callback, AcmeClient,
    std::string url, std::string payload, const char* header = nullptr);

template <typename Callback>
void createAccount(Callback, AcmeClient);

template <typename Callback>
void orderCertificate(Callback, AcmeClient, std::vector<identifier>);

struct Challenge {
    std::string statusUrl;
    std::string identifier;
    std::string location;
    std::string keyAuthorization;
};

struct OrderInfo {
    std::string url;
    std::string finalizeUrl;
    std::vector<identifier> identifiers;
    std::vector<Challenge> challenges;
};

template <typename Callback>
void retrieveCertificate(Callback, AcmeClient, OrderInfo);

template <typename Callback>
void waitForGet(Callback, std::string url, std::chrono::milliseconds timeout, std::chrono::milliseconds interval);

}

#endif /* end of include guard */
