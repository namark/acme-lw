#include "acme-lw.hpp"

namespace acme_lw
{
    std::string toString(enum identifier::type t) {
        switch(t) {
            case identifier::type::ip: return "ip";
            case identifier::type::domain: return "dns";
        }

        return "";
    };

    std::vector<char> toVector(BIO * bio)
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

    std::string toString(BIO *bio)
    {
        std::vector<char> v = toVector(bio);
        return std::string(&v.front(), v.size());
    }

    std::string base64Decode(const std::string& t)
    {
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

    std::string urlSafeBase64Encode(const BIGNUM * bn)
    {
        int numBytes = BN_num_bytes(bn);
        std::vector<unsigned char> buffer(numBytes);
        BN_bn2bin(bn, &buffer.front());

        return urlSafeBase64Encode(buffer);
    }

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

    EVP_PKEYptr makePrivateKey() {

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

    std::string toPemString(const EVP_PKEYptr& key) {
        BIOptr keyBio(BIO_new(BIO_s_mem()));
        if(!keyBio) {
            return std::string();
        }

        if (PEM_write_bio_PrivateKey(keyBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            return std::string();
        }
        return toString(keyBio.get());
    }

    std::pair<std::vector<char>, std::string> makeCertificateSigningRequest(const std::vector<identifier>& identifiers) {

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

    std::string sha256(const std::string& s)
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
    std::string makeJwkThumbprint(const std::string& jwk)
    {
        std::string strippedJwk = jwk;

        // strip whitespace
        strippedJwk.erase(remove_if(strippedJwk.begin(), strippedJwk.end(), ::isspace), strippedJwk.end());

        return sha256(strippedJwk);
    }

} // namespace acme_lw

using namespace acme_lw;

AcmeClient::AcmeClient(
            std::string privateKey,
            std::string newAccountUrl,
            std::string newOrderUrl,
            std::string newNonceUrl,
            std::string eab_kid,
            std::string eab_hmac)
    : impl_(std::make_unique<AcmeClientImpl>(
        std::move(privateKey),
        std::move(newAccountUrl),
        std::move(newOrderUrl),
        std::move(newNonceUrl),
        std::move(eab_kid),
        std::move(eab_hmac)
    ))
{
}

ExpiryTimepointResult Certificate::getExpiryOrError() const
{
    return extractExpiryDataError<std::chrono::system_clock::time_point>(*this, [](const ASN1_TIME * t)
            -> ExpiryTimepointResult
        {
#ifdef OPENSSL_TO_TM
            // Prior to openssl 1.1.1 (or so?) ASN1_TIME_to_tm didn't exist so there was no
            // good way of converting to time_t. If it exists we use the built in function.

            ::tm out;
            if (!ASN1_TIME_to_tm(t, &out))
            {
                return {false, {}, AcmeException("Failure in ASN1_TIME_to_tm")};
            }

            return {
                true,
                std::system_clock::from_time_t(timegm(&out));
                AcmeException("")
            };
#else
            // See this link for issues in converting from ASN1_TIME to epoch time.
            // https://stackoverflow.com/questions/10975542/asn1-time-to-time-t-conversion

            int days, seconds;
            if (!ASN1_TIME_diff(&days, &seconds, nullptr, t))
            {
                return {false, {}, AcmeException("Failure in ASN1_TIME_diff")};
            }

            // Hackery here, since the call to system_clock::now() will not necessarily match
            // the equivilent call openssl just made in the 'diff' call above.
            // Nonetheless, it'll be close at worst.
            return {
                true,
                std::chrono::system_clock::now()
                    + std::chrono::seconds(seconds)
                    + std::chrono::hours(24) * days,
                AcmeException("")
            };

#endif
        });
}

std::chrono::system_clock::time_point Certificate::getExpiry() const
{
    auto ret = getExpiryOrError();
    if(ret.success) {
        return ret.value;
    } else {
        throw ret.error;
    }
}

std::string Certificate::getExpiryDisplay() const
{
    return extractExpiryData<std::string>(*this, [](const ASN1_TIME * t)
        {
            BIOptr b(BIO_new(BIO_s_mem()));
            if (!ASN1_TIME_print(b.get(), t))
            {
                throw AcmeException("Failure in ASN1_TIME_print");
            }

            return toString(b.get());
        });
}
