namespace cryptx {

enum class rsa_bits {
    RSA_1024 = 1024,
    RSA_2048 = 2048,
    RSA_3072 = 3072,
    RSA_4096 = 4096
};

enum class rsa_padding {
    PKCS1,
    OAEP,
    PSS
};

enum class rsa_hash {
    SHA256,
    SHA512
};

} // namespace cryptx


class rsa_exception : public std::runtime_error {
public:
    explicit rsa_exception(const std::string& msg);
};

// 公钥
class rsa_public {
public:
    explicit rsa_public(const std::string& pem);
    explicit rsa_public(const std::filesystem::path& file);
    ~rsa_public();

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                       rsa_padding padding = rsa_padding::OAEP) const;

    bool verify(const std::vector<unsigned char>& message,
                const std::vector<unsigned char>& signature,
                rsa_padding padding = rsa_padding::PSS,
                rsa_hash hash_alg = rsa_hash::SHA256) const;

    std::string pem() const;

private:
    RSA* rsa_ = nullptr;
};

// 私钥
class rsa_private {
public:
    explicit rsa_private(rsa_bits bits = rsa_bits::RSA_2048,
                         const std::string& password = "");

    explicit rsa_private(const std::string& pem, const std::string& password = "");
    explicit rsa_private(const std::filesystem::path& file, const std::string& password = "");

    ~rsa_private();

    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                       rsa_padding padding = rsa_padding::OAEP) const;

    std::vector<unsigned char> sign(const std::vector<unsigned char>& message,
                                    rsa_padding padding = rsa_padding::PSS,
                                    rsa_hash hash_alg = rsa_hash::SHA256) const;

    std::string pem() const;         // 导出私钥 PEM，可加密
    std::string public_pem() const;  // 导出对应公钥 PEM

    rsa_public get_public() const;

    void set_password(const std::string& password);

private:
    RSA* rsa_ = nullptr;
    std::string password_;
};
