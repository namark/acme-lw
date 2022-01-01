#ifndef VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_HPP
#define VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_HPP

#include "ZeroSSL.h"
#include "acme-lw.hpp"
#include "http.hpp"

namespace acme_lw
{

struct ZeroSSLError {
    std::string type;
    std::string info;
};

// a sanity check for API url, we expect an error
template <typename Callback>
void init(Callback callback, std::string apiKey, ZeroSSLRestAPI) {
#ifndef ACME_LW_ZEROSSL_SKIP_SANITY_CHECKS
    acme_lw_internal::doGet(forwardAcmeError(
        [apiKey = std::move(apiKey)](auto next, auto response){
            std::string errorType{};
            try {
                nlohmann::json::parse(response.response_)
                    .at("error").at("type");
            } catch (const std::exception& e) {
                next(AcmeException("ZeroSSL init() failed to parse response: "s + e.what()));
                return;
            }

            next(ZeroSSLClient(std::move(apiKey)));
        },
        std::move(callback)
    ), ZeroSSLRestAPI::URL + "/");
#else
    callback(ZeroSSLClient(std::move(apiKey)));
#endif
}

// sanity check for access key, we expect a specific error
template <typename Callback>
void createAccount(Callback callback, ZeroSSLClient client) {
#ifndef ACME_LW_ZEROSSL_SKIP_SANITY_CHECKS
    auto url = client.addAccessKey(ZeroSSLRestAPI::URL + "/");
    acme_lw_internal::doGet(forwardAcmeError(
        [client = std::move(client)](auto next, auto response){
            std::string errorType{};
            std::string errorInfo{};
            try {
                auto json = nlohmann::json::parse(response.response_);
                auto error = json.at("error");
                errorType = error.at("type").template get<std::string>();
                errorInfo = error.value("info", errorInfo);
            } catch (const std::exception& e) {
                next(std::move(client), AcmeException("ZeroSSL createAccount() failed to parse response: "s + e.what()));
                return;
            }

            if(errorType == "invalid_api_function") {
                next(std::move(client));
            } else {
                next(std::move(client), AcmeException("ZeroSSL createAccount() failed: " + errorInfo));
            }
        },
        std::move(callback)
    ), std::move(url));
#else
    callback(std::move(client));
#endif
}

template <typename Callback>
void orderCertificate(Callback callback, ZeroSSLClient client, std::vector<identifier> identifiers) {
    auto url = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT);

    auto idNameList = join(identifiers, ",", [](auto id) {
        return id.name;
    });

    auto csr = makeCertificateSigningRequest(identifiers);

    acme_lw_internal::doPost(forwardAcmeError([
        client = std::move(client),
        csrKey = std::move(csr.second),
        identifiers = std::move(identifiers)
    ] (auto next, auto response){
        bool errorOccurred = false;
        std::string errorType{};
        std::string errorInfo{};
        nlohmann::json json;
        ZeroSSLOrderInfo orderInfo{};

        try {
            json = nlohmann::json::parse(response.response_);
            if(json.count("error") == 1) {
                errorOccurred = true;
                auto error = json["error"];
                errorType = error.at("type").template get<std::string>();
                errorInfo = error.value("info", "Unknown error: " + errorType);
            } else {
                orderInfo.certId = json.at("id").template get<std::string>();
                orderInfo.csrKey = csrKey;
                orderInfo.identifiers = std::move(identifiers);
                auto validation = json.at("validation").at("other_methods");
                for(auto&& identifier : orderInfo.identifiers) {
                    auto challenge = validation.at(identifier.name);
                    std::string validationUrl = challenge.at("file_validation_url_http");
                    auto locationIndex = validationUrl.find(identifier.name);

                    if (locationIndex == std::string::npos) {
                        throw AcmeException("ZeroSSL orderCertificate() could not extract location form validation url: " + validationUrl);
                    }

                    locationIndex += identifier.name.size();

                    orderInfo.challenges.push_back({
                        "",
                        identifier.name,
                        validationUrl.substr(locationIndex),
                        join(challenge.at("file_validation_content"), "\n")
                    });
                }
            }
        } catch (const std::exception& e) {
            next(std::move(client), AcmeException("ZeroSSL orderCertificate() failed to parse response: "s + e.what()));
            return;
        }

        if(errorOccurred) {
            next(std::move(client), AcmeException("ZeroSSL orderCertificate() failed: " + errorInfo));
            return;
        }

        next(std::move(client), std::move(orderInfo));
    }, std::move(callback)), std::move(url), {
        {"certificate_domains", std::move(idNameList)},
        {"certificate_csr", base64Encode(csr.first)}
    });
}

template <typename Callback>
void waitForValid(Callback callback, ZeroSSLClient client, std::string url, std::chrono::milliseconds timeout, std::chrono::milliseconds interval = 1s) {
    if(timeout <= 0ms) {
        callback(std::move(client), AcmeException("ZeroSSL status check timeout: " + url));
        return;
    }

    auto nextUrl = url; // explicit copy, since can't rely on order of evaluation of function parameters
    // TODO: need to move the url into the callback, preventing the need to capture it
    acme_lw_internal::doGet(
        forwardAcmeError([client = std::move(client), url = nextUrl, timeout, interval](auto next, auto response) mutable {
            int valid = 0;
            try {
                auto json = nlohmann::json::parse(response.response_);
                valid = json.at("validation_completed");
            } catch (const std::exception& e) {
                next(std::move(client), AcmeException("ZeroSSL waitForValid() failed to parse response: "s + e.what()));
                return;
            }
            if(valid == 1) {
               next(std::move(client));
            } else {
               QTimer::singleShot(interval.count(), [next = std::move(next), client = std::move(client), url = std::move(url), timeout, interval]() mutable {
                   waitForValid(std::move(next), std::move(client), std::move(url), timeout - interval, interval);
               });
            }
        }, std::move(callback)),
    std::move(url));
}

template <typename Callback>
void retrieveCertificate(Callback callback, ZeroSSLClient client, ZeroSSLOrderInfo info) {
    auto url = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT + "/" + info.certId + ZeroSSLRestAPI::CHALLENGES);
    acme_lw_internal::doPost(forwardAcmeError([client = std::move(client), info = std::move(info)]
        (auto next, auto response) {
            bool errorOccurred = false;
            std::string errorType{};
            std::string errorInfo{};
            try {
                auto json = nlohmann::json::parse(response.response_);
                if(json.count("error") == 1) {
                    errorOccurred = true;
                    auto error = json["error"];
                    errorType = error.at("type").template get<std::string>();
                    errorInfo = error.value("info", "Unknown error: " + errorType);
                }
            } catch (const std::exception& e) {
                next(std::move(client), AcmeException("ZeroSSL retrieveCertificate() failed to parse response: "s + e.what()));
                return;
            }

            if(errorOccurred) {
                next(std::move(client), AcmeException("ZeroSSL retrieveCertificate() failed: " + errorInfo));
                return;
            }

            auto statusUrl = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT + "/" + info.certId + ZeroSSLRestAPI::STATUS);
            waitForValid(forwardAcmeError([info = std::move(info)](auto next, auto client){
                auto downloadUrl = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT + "/" + info.certId + ZeroSSLRestAPI::DOWNLOAD);
                acme_lw_internal::doGet(forwardAcmeError([client = std::move(client), info = std::move(info)](auto next, auto response){
                    Certificate cert;
                    bool errorOccurred = false;
                    std::string errorType{};
                    std::string errorInfo{};
                    try {
                        auto json = nlohmann::json::parse(response.response_);
                        if(json.count("error") == 1) {
                            errorOccurred = true;
                            auto error = json["error"];
                            errorType = error.at("type").template get<std::string>();
                            errorInfo = error.value("info", "Unknown error: " + errorType);
                        } else {
                            cert.fullchain = json.at("certificate.crt");
                        }
                    } catch (const std::exception& e) {
                        next(std::move(client), AcmeException("ZeroSSL retrieveCertificate() failed to parse response: "s + e.what()));
                        return;
                    }

                    if(errorOccurred) {
                        next(std::move(client), AcmeException("ZeroSSL retrieveCertificate() failed: " + errorInfo));
                        return;
                    }

                    cert.privkey = std::move(info.csrKey);
                    next(std::move(client), std::move(cert));
                }, std::move(next)), downloadUrl);
            }, std::move(next)), std::move(client), std::move(statusUrl), 10s);
        }, std::move(callback)),
        std::move(url), {{"validation_method", "HTTP_CSR_HASH"}}
    );
}

}

#endif /* end of include guard */
