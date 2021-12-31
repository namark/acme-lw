#ifndef VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ACME_LW_HPP
#define VIRCADIA_LIBRARIES_NETWORKING_SRC_ACME_ACME_LW_HPP

/**
 * If you want to work through what the code is actually doing this has an excellent
 * description of the protocol being used.
 *
 * https://github.com/alexpeattie/letsencrypt-fromscratch
 */

#include "acme-lw.h"

#include "http.hpp"

#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/hmac.h>
#include <QTimer>

#include <algorithm>
#include <ctype.h>
#include <stdio.h>
#include <typeinfo>
#include <vector>
#include <string>
#include <functional>
#include <utility>

namespace acme_lw
{

using namespace std::literals;
using acme_lw_internal::Response;

template <typename Range, typename ToString>
std::string join(const Range& rng, const std::string& seperator, ToString toStr) {
    return std::accumulate(rng.begin(), rng.end(), std::string(), [&toStr, &seperator]
    (const auto& all, const auto& one) {
        auto str = toStr(one);
        return all.empty() ? str : all + seperator + str;
    });
}

template <typename Range>
std::string join(const Range& rng, const std::string& seperator) {
    return join(rng, seperator, [](auto&& x)
        -> std::string { return std::forward<decltype(x)>(x); });
}


using acme_lw_internal::Response;
// Smart pointers for OpenSSL types
template <typename T, void(*F)(T*)>
struct freeFunctionDeleteType {
    void operator() (T* t) const { F(t); }
};
template <typename T, void (*D) (T*)>
using Ptr = std::unique_ptr<T,freeFunctionDeleteType<T,D>>;

// TODO: the unique_ptr replacement above does not throw on null like the old version below,
// instead the errors will need to be handled in place and more meaningful exceptions thrown,
// prior to the initial rework openssl was an implementation detail (and will be after full rework),
// so exception referring to it do not make much sense
// template<typename TYPE, void (*FREE)(TYPE *)>
// struct Ptr
// {
//     Ptr()
//         : ptr_(nullptr)
//     {
//     }
//
//     Ptr(TYPE * ptr)
//         : ptr_(ptr)
//     {
//         if (!ptr_)
//         {
//             throw acme_lw::AcmeException("Failed to create "s + typeid(*this).name());
//         }
//     }
//
//     ~Ptr()
//     {
//         if (ptr_)
//         {
//             FREE(ptr_);
//         }
//     }
//
//     Ptr& operator = (Ptr&& ptr)
//     {
//         if (!ptr.ptr_)
//         {
//             throw acme_lw::AcmeException("Failed to create "s + typeid(*this).name());
//         }
//
//         ptr_ = move(ptr.ptr_);
//         ptr.ptr_ = nullptr;
//
//         return *this;
//     }
//
//     bool operator ! () const
//     {
//         return !ptr_;
//     }
//
//     TYPE * operator * () const
//     {
//         return ptr_;
//     }
//
//     void clear()
//     {
//         ptr_ = nullptr;
//     }
//
// private:
//     TYPE * ptr_;
// };

typedef Ptr<BIO, BIO_free_all>                                  BIOptr;
typedef Ptr<RSA, RSA_free>                                      RSAptr;
typedef Ptr<BIGNUM, BN_clear_free>                              BIGNUMptr;
typedef Ptr<EVP_MD_CTX, EVP_MD_CTX_free>                        EVP_MD_CTXptr;
typedef Ptr<EVP_PKEY, EVP_PKEY_free>                            EVP_PKEYptr;
typedef Ptr<X509, X509_free>                                    X509ptr;
typedef Ptr<X509_REQ, X509_REQ_free>                            X509_REQptr;


inline void freeStackOfExtensions(STACK_OF(X509_EXTENSION) * e)
{
    sk_X509_EXTENSION_pop_free(e, X509_EXTENSION_free);
}

typedef Ptr<STACK_OF(X509_EXTENSION), freeStackOfExtensions>    X509_EXTENSIONSptr;

template<typename T>
T toT(const std::vector<char>& v)
{
    return v;
}

template<>
inline std::string toT<std::string>(const std::vector<char>& v)
{
    return std::string(&v.front(), v.size());
}

inline std::vector<char> toVector(BIO * bio)
{
    constexpr int buffSize = 1024;

    std::vector<char> buffer(buffSize);

    size_t pos = 0;
    int count = 0;
    do
    {
        count = BIO_read(bio, &buffer.front() + pos, buffSize);
        if (count > 0)
        {
            pos += count;
            buffer.resize(pos + buffSize);
        }
    }
    while (count > 0);

    buffer.resize(pos);

    return buffer;
}

inline std::string toString(BIO *bio)
{
    std::vector<char> v = toVector(bio);
    return std::string(&v.front(), v.size());
}

std::string base64Decode(const std::string& t)
{
	// TODO:
    if (!t.size()) {
        return "";
    }
    // Use openssl to do this since we're already linking to it.

    // Don't need (or want) a BIOptr since BIO_push chains it to b64
    BIO * bio(BIO_new_mem_buf(&t.front(), t.size()));
    BIOptr b64(BIO_new(BIO_f_base64()));

    // OpenSSL inserts new lines by default to make it look like PEM format.
    // Turn that off.
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO_push(b64.get(), bio);
	std::string output(t.size(), 0);
	auto read = BIO_read(b64.get(), &output.front(), output.size());
	if(read <= 0) {
		throw acme_lw::AcmeException("Failure in base64Decode, BIO_read returned " + std::to_string(read) + '\n'
            + "input: " + t + '\n'
            + "output: " + output + '\n');
	}
	output.resize(read);

    return output;
}

template<typename T>
std::string base64Encode(const T& t)
{
    if (!t.size())
    {
        return "";
    }
    // Use openssl to do this since we're already linking to it.

    // Don't need (or want) a BIOptr since BIO_push chains it to b64
    BIO * bio(BIO_new(BIO_s_mem()));
    BIOptr b64(BIO_new(BIO_f_base64()));

    // OpenSSL inserts new lines by default to make it look like PEM format.
    // Turn that off.
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);

    BIO_push(b64.get(), bio);
    if (BIO_write(b64.get(), &t.front(), t.size()) <= 0 ||
        BIO_flush(b64.get()) < 0)
    {
        throw acme_lw::AcmeException("Failure in BIO_write / BIO_flush");
    }

    return toString(bio);
}

std::string urlSafeBase64Decode(std::string s)
{
    // We get url safe base64 encoding and openssl requires regular
    // base64, so we convert.

    for(auto&& ch : s)
    {
        if (ch == '-')
        {
            ch = '+';
        }
        else if (ch == '_')
        {
            ch = '/';
        }
    }

    const std::size_t fullChunkSize = 4;
    auto trailing = s.size() % fullChunkSize;
    auto lastChunkSize = 0 != trailing ? trailing : fullChunkSize;
    auto padding = fullChunkSize - lastChunkSize;
    s += std::string(padding,'=');

    return base64Decode(s);
}

template<typename T>
std::string urlSafeBase64Encode(const T& t)
{
    std::string s = base64Encode(t);

    // We need url safe base64 encoding and openssl only gives us regular
    // base64, so we convert.
    size_t len = s.size();
    for (size_t i = 0; i < len; ++i)
    {
        if (s[i] == '+')
        {
            s[i] = '-';
        }
        else if (s[i] == '/')
        {
            s[i] = '_';
        }
        else if (s[i] == '=')
        {
            s.resize(i);
            break;
        }
    }

    return s;
}

inline std::string urlSafeBase64Encode(const BIGNUM * bn)
{
    int numBytes = BN_num_bytes(bn);
    std::vector<unsigned char> buffer(numBytes);
    BN_bn2bin(bn, &buffer.front());

    return urlSafeBase64Encode(buffer);
}

struct hmacAlg {
    std::string name;
    const EVP_MD* evp_md;
};

hmacAlg getHmacAlg(const std::string& key)
{
    struct keySizeAlgPair {
        std::size_t keySize;
        hmacAlg alg;
    };

    const std::array<keySizeAlgPair,3> map {{
        {32, {"HS256", EVP_sha256()}},
        {64, {"HS512", EVP_sha512()}},
        {48, {"HS384", EVP_sha384()}}
    }};

    auto found = std::find_if(map.begin(), map.end(),
        [keySize = key.size()] (auto pair) { return keySize == pair.keySize; });

    if(found == map.end()) {
        auto expected = join(map, ", ", [](const auto& pair) {
            return "size " + std::to_string(pair.keySize) + " for " + pair.alg.name;
        });
        throw AcmeException("Unexpected HMAC key size: " + std::to_string(key.size()) + '\n'
            + "key: " + urlSafeBase64Encode(key) + '\n'
            + "expected: " + expected + '\n'
        );
    }

    return found->alg;
}

std::string hmacSha(const std::string& key, const std::string& data)
{
    auto alg = getHmacAlg(key);
	std::string output(EVP_MAX_MD_SIZE, 0);
	unsigned int output_size = output.size();
	if (! HMAC(alg.evp_md, key.data(), key.size(),
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        reinterpret_cast<unsigned char*>(&output.front()), &output_size)
       )
    {
        throw AcmeException("Failed to generate HMAC signature\n"s
            + "key: " + urlSafeBase64Encode(key) + '\n'
            + "data: " + data + '\n'
            + "alg: " + alg.name
        );
    }
	output.resize(output_size);
	return output;
}

inline EVP_PKEYptr makePrivateKey() {

    BIGNUMptr bn(BN_new());
    if(!bn) {
        throw acme_lw::AcmeException("Failure in BN_new");
    }

    if (!BN_set_word(bn.get(), RSA_F4)) {
        throw acme_lw::AcmeException("Failure in BN_set_word");
    }

    RSAptr rsa(RSA_new());
    if(!rsa) {
        throw acme_lw::AcmeException("Failure in RSA_new");
    }

    int bits = 2048;
    if (!RSA_generate_key_ex(rsa.get(), bits, bn.get(), nullptr))
    {
        throw acme_lw::AcmeException("Failure in RSA_generate_key_ex");
    }

    EVP_PKEYptr key(EVP_PKEY_new());
    if(!key) {
        throw acme_lw::AcmeException("Failure in EVP_PKEY_new");
    }
    // rsa will be freed when key is freed.
    if (!EVP_PKEY_assign_RSA(key.get(), rsa.release()))
    {
        throw acme_lw::AcmeException("Failure in EVP_PKEY_assign_RSA");
    }

    return key;

}

inline std::string toPemString(const EVP_PKEYptr& key) {
    BIOptr keyBio(BIO_new(BIO_s_mem()));
    if(!keyBio) {
        return std::string();
    }

    if (PEM_write_bio_PrivateKey(keyBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return std::string();
    }
    return toString(keyBio.get());
}

// returns pair<CSR, privateKey>
inline std::pair<std::vector<char>, std::string> makeCertificateSigningRequest(const std::vector<identifier>& identifiers) {

    X509_REQptr req(X509_REQ_new());

    auto identifier = identifiers.begin();

    X509_NAME * cn = X509_REQ_get_subject_name(req.get());
    if (!X509_NAME_add_entry_by_txt(cn,
                                    "CN",
                                    MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>(identifier->name.c_str()),
                                    -1, -1, 0))
    {
        throw acme_lw::AcmeException("Failure in X509_Name_add_entry_by_txt");
    }

    if (++identifier != identifiers.end())
    {
        // We have one or more Subject Alternative Names
        X509_EXTENSIONSptr extensions(sk_X509_EXTENSION_new_null());

        std::string value;
        do
        {
            if (!value.empty())
            {
                value += ", ";
            }
            value += toString(identifier->type) + ":" + identifier->name;
        }
        while (++identifier != identifiers.end());

        if (!sk_X509_EXTENSION_push(extensions.get(), X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, value.c_str())))
        {
            throw acme_lw::AcmeException("Unable to add Subject Alternative Name to extensions");
        }

        if (X509_REQ_add_extensions(req.get(), extensions.get()) != 1)
        {
            throw acme_lw::AcmeException("Unable to add Subject Alternative Names to CSR");
        }
    }

    auto key = makePrivateKey();

    std::string privateKey = toPemString(key);

    if (!X509_REQ_set_pubkey(req.get(), key.get()))
    {
        throw acme_lw::AcmeException("Failure in X509_REQ_set_pubkey");
    }

    if (!X509_REQ_sign(req.get(), key.get(), EVP_sha256()))
    {
        throw acme_lw::AcmeException("Failure in X509_REQ_sign");
    }

    BIOptr reqBio(BIO_new(BIO_s_mem()));
    if (i2d_X509_REQ_bio(reqBio.get(), req.get()) < 0)
    {
        throw acme_lw::AcmeException("Failure in i2d_X509_REQ_bio");
    }

    return make_pair(toVector(reqBio.get()), privateKey);
}

inline std::string sha256(const std::string& s)
{
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256) ||
        !SHA256_Update(&sha256, s.c_str(), s.size()) ||
        !SHA256_Final(&hash.front(), &sha256))
    {
        throw acme_lw::AcmeException("Error hashing a string");
    }

    return urlSafeBase64Encode(hash);
}

// https://tools.ietf.org/html/rfc7638
inline std::string makeJwkThumbprint(const std::string& jwk)
{
    std::string strippedJwk = jwk;

    // strip whitespace
    strippedJwk.erase(remove_if(strippedJwk.begin(), strippedJwk.end(), ::isspace), strippedJwk.end());

    return sha256(strippedJwk);
}

template <typename T>
ExpiryResult<T> makeExpiryResult(T value) { return {true, value, AcmeException("")}; }
template <typename T>
ExpiryResult<T> makeExpiryResult(ExpiryResult<T> value) { return value; }

template<typename T, typename Extractor>
ExpiryResult<T> extractExpiryDataError(const acme_lw::Certificate& certificate, const Extractor& extractor)
{
    BIOptr bio(BIO_new(BIO_s_mem()));
    if (BIO_write(bio.get(), &certificate.fullchain.front(), certificate.fullchain.size()) <= 0)
    {
        return {false, T{}, acme_lw::AcmeException("Failure in BIO_write")};
    }
    X509ptr x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));

    ASN1_TIME * t = X509_getm_notAfter(x509.get());

    return makeExpiryResult(extractor(t));
}

template<typename T, typename Extractor>
T extractExpiryData(const acme_lw::Certificate& certificate, const Extractor& extractor)
{
    auto ret = extractExpiryDataError<T>(certificate, extractor);
    if(ret.success) {
        return ret.value;
    } else {
        throw ret.error;
    }
}

}

namespace acme_lw
{

struct AcmeClientImpl
{
    AcmeClientImpl(
            std::string accountPrivateKey,
            std::string newAccountUrl,
            std::string newOrderUrl,
            std::string newNonceUrl,
            // TODO: implement External Account Binding
            std::string eab_kid = "",
            std::string eab_hmac = ""
    )
        : privateKey_(EVP_PKEY_new()),
        newAccountUrl_(std::move(newAccountUrl)),
        newOrderUrl_(std::move(newOrderUrl)),
        newNonceUrl_(std::move(newNonceUrl)),
		eab_kid_(eab_kid),
		eab_hmac_(urlSafeBase64Decode(eab_hmac))
    {
        // Create the private key and 'header suffix', used to sign LE certs.
        BIOptr bio(BIO_new_mem_buf(accountPrivateKey.c_str(), -1));
        RSA * rsa(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
        if (!rsa)
        {
            throw AcmeException("Unable to read private key");
        }

        // rsa will get freed when privateKey_ is freed
        if (!EVP_PKEY_assign_RSA(privateKey_.get(), rsa))
        {
            throw AcmeException("Unable to assign RSA to private key");
        }

        const BIGNUM *n, *e, *d;
        RSA_get0_key(rsa, &n, &e, &d);

        // Note json keys must be in lexographical order.
        std::string jwkValue = u8R"( {
                                    "e":")"s + urlSafeBase64Encode(e) + u8R"(",
                                    "kty": "RSA",
                                    "n":")"s + urlSafeBase64Encode(n) + u8R"("
                                })";
		jwk_ = jwkValue;
        jwkThumbprint_ = makeJwkThumbprint(jwkValue);

        // We use jwk for the first request, which allows us to get
        // the account id. We use that thereafter.
        headerSuffix = u8R"(
                "alg": "RS256",
                "jwk": )" + jwkValue + "}";

    }

    std::string sign(const std::string& s)
    {
        // https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
        size_t signatureLength = 0;

        EVP_MD_CTXptr context(EVP_MD_CTX_create());
        const EVP_MD * sha256 = EVP_get_digestbyname("SHA256");
        if (!sha256 ||
            EVP_DigestInit_ex(context.get(), sha256, nullptr) != 1 ||
            EVP_DigestSignInit(context.get(), nullptr, sha256, nullptr, privateKey_.get()) != 1 ||
            EVP_DigestSignUpdate(context.get(), s.c_str(), s.size()) != 1 ||
            EVP_DigestSignFinal(context.get(), nullptr, &signatureLength) != 1)
        {
            throw AcmeException("Error creating SHA256 digest");
        }

        std::vector<unsigned char> signature(signatureLength);
        if (EVP_DigestSignFinal(context.get(), &signature.front(), &signatureLength) != 1)
        {
            throw AcmeException("Error creating SHA256 digest in final signature");
        }

        return urlSafeBase64Encode(signature);
    }

    const std::string& newAccountUrl() { return newAccountUrl_; }
    const std::string& newOrderUrl() { return newOrderUrl_; }
    const std::string& newNonceUrl() { return newNonceUrl_; }
    const std::string& eab_kid() { return eab_kid_; }
    const std::string& eab_hmac() { return eab_hmac_; }
    const std::string& jwkThumbprint() { return jwkThumbprint_; }
    const std::string& jwk() { return jwk_; }

    std::string      headerSuffix;

    private:
    EVP_PKEYptr privateKey_;
    std::string      jwkThumbprint_;
    std::string      jwk_;

    std::string newAccountUrl_;
    std::string newOrderUrl_;
    std::string newNonceUrl_;
	std::string eab_kid_;
	std::string eab_hmac_;

};

// TODO: c++17 fold expressions replace this
template<bool...> struct conjunction;
template<> struct conjunction<> : std::true_type { };
template<bool B1, bool... Bn>
struct conjunction<B1, Bn...>
{constexpr static bool value = B1 && conjunction<Bn...>::value;};
template <bool... Bn>
constexpr static bool conjunction_v = conjunction<Bn...>::value;

template <typename Body, typename Next>
struct ForwardAcmeError
{
    ForwardAcmeError(Body body, Next next) :
        body(std::move(body)),
        next(std::move(next))
    {}

    void operator()(AcmeException error) const {
        next(std::move(error));
    }

    template <typename Client>
    void operator()(Client client, AcmeException error) const {
        next(std::move(client), std::move(error));
    }

    template <typename... Ts,
        std::enable_if_t<conjunction_v<not std::is_same<Ts,AcmeException>::value...>>* = nullptr>
    void operator()(Ts&&... values) {
        body(std::move(next), std::forward<Ts>(values)...);
    }

    private:
    Body body;
    Next next;
};

template <typename Body, typename Next>
ForwardAcmeError<Body, Next> forwardAcmeError(Body&& body, Next&& next) {
    return {std::forward<Body>(body), std::forward<Next>(next)};
}

template <typename F>
struct CaptureAcmeClient
{
    CaptureAcmeClient(AcmeClient client, F f) :
        client(std::move(client)),
        f(std::move(f))
    {}

    void operator()(AcmeException error) {
        f(std::move(client), std::move(error));
    }

    template <typename T>
    void operator()(T&& value) {
        f(std::move(client), std::forward<T>(value));
    }

    private:
    AcmeClient client;
    F f;
};

template <typename F>
CaptureAcmeClient<F> captureAcmeClient(AcmeClient client, F&& f) {
    return {std::move(client), std::forward<F>(f)};
}

template <typename Callback>
void init(Callback callback, std::string signingKey, std::string directoryUrl, std::string eab_kid, std::string eab_hmac) {
    acme_lw_internal::doGet(forwardAcmeError(
        [signingKey = std::move(signingKey),
        directoryUrl,
		eab_kid = std::move(eab_kid),
		eab_hmac = std::move(eab_hmac)]
        (auto next, acme_lw_internal::Response result) {
            try {
                auto json = nlohmann::json::parse(result.response_);
				bool externalAccountRequired = json["meta"].value("externalAccountRequired", false);
				if(externalAccountRequired && (eab_kid.empty() || eab_hmac.empty())) {
					next(AcmeException("External account binding is required for " + directoryUrl)); // TODO: move out of try
				} else {
					AcmeClient client(
						std::move(signingKey),
						json.at("newAccount"),
						json.at("newOrder"),
						json.at("newNonce"),
						externalAccountRequired ? std::move(eab_kid) : "",
						externalAccountRequired ? std::move(eab_hmac) : ""
                    );
					next(std::move(client)); // TODO: move out of try
				}
            } catch (const std::exception& e) {
                next(AcmeException("Unable to initialize endpoints from "s + directoryUrl + " : " + e.what() + '\n'
                    + toT<std::string>(result.response_)));
            }

        }, std::move(callback)
    ), std::move(directoryUrl));
}

template <typename Callback>
void sendRequest(Callback callback, AcmeClient client,
    std::string url, std::string payload, const char* header)
{
    auto nonseUrl = client.impl_->newNonceUrl();
    acme_lw_internal::getHeader(
        captureAcmeClient(std::move(client),
            forwardAcmeError(
                [url = std::move(url), payload = std::move(payload), header]
                (auto next, auto client, auto replyNonce) {

                    std::string protectd = u8R"({"nonce": ")"s +
                                                replyNonce + "\"," +
                                                u8R"("url": ")" + url + "\"," +
                                                client.impl_->headerSuffix;

                    protectd = urlSafeBase64Encode(protectd);
                    std::string payld = urlSafeBase64Encode(payload);

                    std::string signature = client.impl_->sign(protectd + "." + payld);

                    std::string body = "{"s +
                                    u8R"("protected": ")" + protectd + "\"," +
                                    u8R"("payload": ")" + payld + "\"," +
                                    u8R"("signature": ")" + signature + "\"}";

                    acme_lw_internal::doPost(captureAcmeClient(std::move(client), std::move(next)),
                        std::move(url), std::move(body), header);

                },
            std::move(callback))
        ),
        nonseUrl, "replay-nonce"
    );
}

template <typename Callback>
void createAccount(Callback callback, AcmeClient client) {
    std::pair<std::string, std::string> header = make_pair("location"s, ""s);
    auto newAccountUrl = client.impl_->newAccountUrl();
	nlohmann::json payload = {{"termsOfServiceAgreed", true}};

	if(!client.impl_->eab_kid().empty()) {
        try {
            // NOTE: alg and signature below can be inlined if https://github.com/nlohmann/json/issues/3215 is fixed
            auto alg = getHmacAlg(client.impl_->eab_hmac());
            std::string eabProtected = urlSafeBase64Encode(nlohmann::json({
                {"alg", alg.name},
                {"kid", client.impl_->eab_kid()},
                {"url", newAccountUrl}
            }).dump());
            std::string eabPayload = urlSafeBase64Encode(client.impl_->jwk());
            std::string signature = urlSafeBase64Encode(hmacSha(client.impl_->eab_hmac(), eabProtected + "." + eabPayload));
            payload["externalAccountBinding"] = {
                {"signature", std::move(signature) },
                {"protected", std::move(eabProtected)},
                {"payload", std::move(eabPayload)},
            };
        } catch (const AcmeException& e) {
            callback(std::move(client), AcmeException("EAB payload error: "s + e.what()));
            return;
        }
	}

    sendRequest(
        forwardAcmeError([](auto next, auto client, auto response){
            client.impl_->headerSuffix = u8R"(
                    "alg": "RS256",
                    "kid": ")" + response.headerValue_ + "\"}";
            next(std::move(client));
        }, std::move(callback)),
        std::move(client),
        std::move(newAccountUrl),
		payload.dump(),
        "location"
    );
}

template <typename Range>
class InStack
{
    public:
    InStack(Range range) : range_(range), top_()
    {}

    bool empty() { return top_ == std::end(range_) - std::begin(range_); };
    auto& top() { return *(std::begin(range_) + top_); }
    auto& pop() { return ++top_; }

    operator Range() && {
        return std::move(range_);
    }

    private:
    Range range_;
    typename Range::difference_type top_;
};

template <typename Range>
InStack<Range> makeInStack(Range range)
{
    return {std::move(range)};
}

template <typename T>
class OutStack
{
    public:
    OutStack() : data()
    {}

    bool empty() { return data.empty(); };
    auto& top() { return *(data.end() -1); }
    void push(const T& value) { data.push_back(value); }
    void push(T&& value) { data.push_back(std::move(value)); }
    template <typename V>
    void push(V&& value) { data.push_back(std::forward<V>(value)); }

    operator std::vector<T>() && {
        return std::move(data);
    }

    private:
    std::vector<T> data;
};

template <typename Callback, typename In>
void processAuthorizations(Callback callback, AcmeClient client, InStack<In> autorizations, OutStack<Challenge> challenges)
{
    if(autorizations.empty()) {
        callback(std::move(client), std::move(challenges));
        return;
    }

    std::string authUrl = std::move(autorizations.top());
    autorizations.pop();
    sendRequest(
        forwardAcmeError(
            [autorizations = std::move(autorizations), challenges = std::move(challenges)]
            (auto next, auto client, auto response) mutable {
                // TODO: lots of potential json parsing exceptions here, need to wrap them in high level acme exceptions and pass to callback
                auto authz = nlohmann::json::parse(response.response_);
                /**
                 * If you pass a challenge, that's good for 300 days. The cert is only good for 90.
                 * This means for a while you can re-issue without passing another challenge, so we
                 * check to see if we need to validate again.
                 *
                 * Note that this introduces a race since it possible for the status to not be valid
                 * by the time the certificate is requested. The assumption is that client retries
                 * will deal with this.
                 */
                if (authz.at("status") == "valid") {
                    processAuthorizations(
                        std::move(next),
                        std::move(client),
                        std::move(autorizations),
                        std::move(challenges));
                    return;
                }

                std::string identifier = authz.at("identifier").at("value");

                auto challengesJson = authz.at("challenges");
                auto httpChallenge = std::find_if(challengesJson.begin(), challengesJson.end(),
                    [](auto challenge){ return challenge.at("type") == "http-01"; });

                if(httpChallenge == challengesJson.end()) {
                    next(std::move(client), AcmeException("Http challenge not found for " + identifier));
                    return;
                }

                std::string token = httpChallenge->at("token");
                std::string location = "/.well-known/acme-challenge/"s + token;
                std::string keyAuthorization = token + "." + client.impl_->jwkThumbprint();
                challenges.push({httpChallenge->at("url"), identifier, location, keyAuthorization});
                processAuthorizations(
                    std::move(next),
                    std::move(client),
                    std::move(autorizations),
                    std::move(challenges));
            },
            std::move(callback)
        ),
        std::move(client), authUrl, ""
    );
}

template <typename Callback>
void orderCertificate(Callback callback, AcmeClient client, std::vector<identifier> identifiers) {
    if (identifiers.empty()) {
        callback(std::move(client), AcmeException("There must be at least one identifier name in a certificate"));
        return;
    }

    // Create the order
    std::string payload = u8R"({"identifiers": [)";
    bool first = true;
    for (const identifier& identifier : identifiers)
    {
		/*
		Just check for a '"' in the identifier name to make sure that we send
		a validly formed json payload. The acme service should validate
		that the identifier name is well formed.
		*/
		if (identifier.name.find('"') != std::string::npos)
		{
			callback(std::move(client), AcmeException("Certificate requested for invalid identifier name: "s + identifier.name));
			return;
		}

        if (!first)
        {
            payload += ",";
        }
        first = false;

        payload += u8R"(
                        {
                            "type": ")"s + toString(identifier.type) + u8R"(",
                            "value": ")"s + identifier.name + u8R"("
                        }
                       )";
    }
    payload += "]}";

    std::pair<std::string, std::string> header = make_pair("location"s, ""s);
    auto newOrderUrl = client.impl_->newOrderUrl();
    sendRequest(
        forwardAcmeError(
            [ identifiers = std::move(identifiers) ]
            (auto next, auto client, auto response) mutable {

                std::string currentOrderUrl = response.headerValue_;

                // TODO: try
                auto json = nlohmann::json::parse(response.response_);
                auto authorizations = json.at("authorizations");

                processAuthorizations(
                    forwardAcmeError(
                        [identifiers = std::move(identifiers), currentOrderUrl = std::move(response.headerValue_), finalizeUrl = json.at("finalize")]
                        (auto next, auto client, auto challenges) mutable {
                            next(std::move(client), OrderInfo{
                                std::move(currentOrderUrl),
                                std::move(finalizeUrl),
                                std::move(identifiers),
                                std::move(challenges)
                            });
                        },
                        std::move(next)
                    ),
                    std::move(client), makeInStack(authorizations), OutStack<Challenge>()
                );

            },
            std::move(callback)
        ),
        std::move(client), newOrderUrl, payload, "location"
    );
}

template <typename Callback>
void waitForGet(Callback callback, std::string url, std::chrono::milliseconds timeout, std::chrono::milliseconds interval) {

    struct retryCallback {
        void operator()(Response response) {
            callback(std::move(response));
        }
        void operator()(AcmeException error) {
            if(timeout <= 0ms) {
                callback(AcmeException("Get request timeout: " + std::move(url) + '\n' + error.what()));
            } else {
                QTimer::singleShot(interval.count(), [callback = std::move(callback), url = std::move(url), timeout = timeout, interval = interval]() mutable {
                    waitForGet(std::move(callback), std::move(url), timeout - interval, interval);
                });
            }
        }

        std::string url;
        Callback callback;
        std::chrono::milliseconds timeout;
        std::chrono::milliseconds interval;
    } retryCallback{url, std::move(callback), timeout, interval}; // url is copied, can't move, since doGet also needs it
    // TODO: doGet(and others) need to accept url by value and move it into the callback, preventing the need to capture it,
    // NOTE: it seems like it's only necessary in error case
    acme_lw_internal::doGet(std::move(retryCallback), url);
}

template <typename Callback>
void waitForValid(Callback callback, AcmeClient client, std::string url, std::chrono::milliseconds timeout, std::chrono::milliseconds interval = 1s) {
    if(timeout <= 0ms) {
        callback(std::move(client), AcmeException("Status check timeout: " + url));
        return;
    }

    auto nextUrl = url; // explicit copy, since can't rely on order of evaluation of function parameters
    // TODO: sendRequest need to move the url into the callback, preventing the need to capture it
    sendRequest(
        forwardAcmeError([url = nextUrl, timeout, interval](auto next, auto client, auto response) mutable {
            auto json = nlohmann::json::parse(response.response_);
            if(json.at("status") == "valid") {
               next(std::move(client));
            } else {
               QTimer::singleShot(interval.count(), [next = std::move(next), client = std::move(client), url = std::move(url), timeout, interval]() mutable {
                   waitForValid(std::move(next), std::move(client), std::move(url), timeout - interval, interval);
               });
            }
        }, std::move(callback)),
    std::move(client), std::move(url), "");
}

template <typename Callback>
void checkChallenges(Callback callback, AcmeClient client, InStack<std::vector<std::string>> challenges) {
    if(challenges.empty()) {
        callback(std::move(client));
        return;
    }

    auto challenge = std::move(challenges.top());
    challenges.pop();
    sendRequest(forwardAcmeError(
        [challenges = std::move(challenges)]
        (auto next, auto client, auto response) mutable {
            auto json = nlohmann::json::parse(response.response_);
            if(json.at("status") == "valid") {
                checkChallenges(std::move(next), std::move(client), std::move(challenges));
                return;
            }
            // TODO: detect invalid status and use Retry-After header
            waitForValid(
                forwardAcmeError([challenges = std::move(challenges)](auto next, auto client){
                    checkChallenges(std::move(next), std::move(client), std::move(challenges));
                }, std::move(next)),
            std::move(client), std::move(json.at("url")), 10s);
        },
    std::move(callback)), std::move(client), std::move(challenge), "{}");
}

template <typename Callback>
void retrieveCertificate(Callback callback, AcmeClient client, OrderInfo orderInfo) {
    std::vector<std::string> challengeUrls;
    for(auto&& challenge : orderInfo.challenges) {
        challengeUrls.push_back(std::move(challenge.statusUrl));
    }
    checkChallenges(
        forwardAcmeError([
            identifiers = std::move(orderInfo.identifiers),
            orderUrl = std::move(orderInfo.url),
            finalizeUrl = std::move(orderInfo.finalizeUrl)
        ](auto next, auto client) mutable {
            // TODO: try
            auto r = makeCertificateSigningRequest(identifiers);
            std::string csr = urlSafeBase64Encode(r.first);
            std::string privateKey = r.second;
            sendRequest(
                forwardAcmeError([
                    orderUrl = std::move(orderUrl),
                    privateKey = std::move(privateKey)
                ](auto next, auto client,  auto response) mutable {
                    auto certUrl = nlohmann::json::parse(response.response_).at("certificate");
                    waitForValid(forwardAcmeError([
                        certUrl = std::move(certUrl),
                        privateKey = std::move(privateKey)
                    ](auto next, auto client) mutable {
                        sendRequest(forwardAcmeError([
                            privateKey = std::move(privateKey)
                        ] (auto next, auto client, auto response) mutable {
                            next(std::move(client), Certificate{
                                toT<std::string>(response.response_),
                                std::move(privateKey)
                            });
                        }, std::move(next)), std::move(client), std::move(certUrl), "");
                    }, std::move(next)), std::move(client), std::move(orderUrl), 10s);
                }, std::move(next)),
                std::move(client),
                std::move(finalizeUrl),
                u8R"({
                        "csr": ")"s + csr + u8R"("
                     })"
            );
        }, std::move(callback)),
    std::move(client), std::move(challengeUrls));
}

}

#endif /* end of include guard */
