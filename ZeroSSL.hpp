#ifndef VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_HPP
#define VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ZEROSSL_HPP

#include "ZeroSSL.h"
#include "acme-lw.hpp"
#include "http.hpp"

namespace acme_lw
{

// a sanity check for API url, we expect an error
template <typename Callback>
void init(Callback callback, std::string apiKey, ZeroSSLRestAPI) {
    // There is no documented ZeroSSL API that can serve as sanity check here
    // akin to acme directory. API key validity is checked in createAccount,
    // this step ideally should just verify that the API base URL is correct.
    callback(ZeroSSLClient(std::move(apiKey)));
}

// sanity check for access key, we expect a specific error
template <typename Callback>
void createAccount(Callback callback, ZeroSSLClient client) {
#ifndef ACME_LW_ZEROSSL_SKIP_SANITY_CHECKS
    auto url = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT);
    acme_lw_internal::doGet(forwardAcmeError(
        [client = std::move(client)](auto next, auto response){
            std::string errorInfo{};
            std::string errorType{};
            bool apiError = false;
            try {
                auto json = nlohmann::json::parse(response.response_);
                if(json.count("error") == 1) {
                    apiError = true;
                    auto error = json["error"];
                    errorType = error.at("type").template get<std::string>();
                    errorInfo = error.value("info", "Unknown error: " + errorType);
                } else {
                    json.at("total_count");
                }
            } catch (const std::exception& e) {
                next(std::move(client), AcmeException("ZeroSSL createAccount() failed to parse response: "s + e.what()));
                return;
            }

            if(apiError) {
                next(std::move(client), AcmeException("ZeroSSL createAccount() failed: " + errorInfo));
            } else {
                next(std::move(client));
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

template <typename Callback, typename Value>
void waitForValid(Callback callback, ZeroSSLClient client, std::string url, std::string key, Value value, std::chrono::milliseconds timeout, std::chrono::milliseconds interval = 1s, std::vector<AcmeException> errors = {}) {
    if(timeout <= 0ms) {
        auto errorLog = join(errors, "\n", [](auto error) {
            return error.what();
        });
        callback(std::move(client), AcmeException("ZeroSSL status check timeout: " + url + "\n" +
            "Error log:\n" + errorLog));
        return;
    }

    auto nextUrl = url; // explicit copy, since can't rely on order of evaluation of function parameters
    // TODO: need to move the url into the callback, preventing the need to capture it
    acme_lw_internal::doGet(
        forwardAcmeError([
            client = std::move(client), url = nextUrl,
            key = std::move(key), value = std::move(value),
            timeout, interval,
            errors = std::move(errors)
        ](auto next, auto response) mutable {
            Value valid{};
            try {
                auto json = nlohmann::json::parse(response.response_);
                valid = json.at(key).template get<Value>();
            } catch (const std::exception& e) {
                errors.push_back(AcmeException("ZeroSSL waitForValid() failed to parse response: "s + e.what()));
                waitForValid(std::move(next), std::move(client),
                    std::move(url), std::move(key), std::move(value),
                    timeout - interval, interval,
                    std::move(errors)
                );
                return;
            }
            if(valid == value) {
                next(std::move(client));
            } else {
                QTimer::singleShot(interval.count(), [
                    next = std::move(next), client = std::move(client), url = std::move(url),
                    key = std::move(key), value = std::move(value), timeout, interval,
                    errors = std::move(errors)
                ]() mutable {
                    waitForValid(std::move(next), std::move(client),
                        std::move(url), std::move(key), std::move(value),
                        timeout - interval, interval,
                        std::move(errors)
                    );
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
                auto certUrl = client.addAccessKey(ZeroSSLRestAPI::URL + ZeroSSLRestAPI::CERT_ENDPOINT + "/" + info.certId);
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
                                cert.fullchain = json.at("certificate.crt").template get<std::string>();
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
                }, std::move(next)), std::move(client), std::move(certUrl), "status", "issued"s, 60s);
            }, std::move(next)), std::move(client), std::move(statusUrl), "validation_completed", 1, 60s);
        }, std::move(callback)),
        std::move(url), {{"validation_method", "HTTP_CSR_HASH"}}
    );
}

}

#endif /* end of include guard */
