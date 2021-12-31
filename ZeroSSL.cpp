#include "ZeroSSL.h"

namespace acme_lw
{

const std::string ZeroSSLRestAPI::URL = "http://api.zerossl.com";
const std::string ZeroSSLRestAPI::CERT_ENDPOINT = "/certificates";
const std::string ZeroSSLRestAPI::CHALLENGES = "/challenges";
const std::string ZeroSSLRestAPI::STATUS = "/status";
const std::string ZeroSSLRestAPI::DOWNLOAD = "/download/return";

ZeroSSLClient::ZeroSSLClient(std::string apiKey) :
    apiKey(apiKey)
{}

std::string ZeroSSLClient::addAccessKey(std::string url) const {
    return url + "?access_key=" + apiKey;
}

}
