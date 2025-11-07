#pragma once

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptx
{
namespace rsa
{

enum class bits
{
  RSA_1024 = 1024,
  RSA_2048 = 2048,
  RSA_3072 = 3072,
  RSA_4096 = 4096
};

// hash 枚举保留，仅用于签名/验签时的 PSS 签名算法
enum class hash
{
  SHA256,
  SHA512
};

class rsa_exception : public std::runtime_error
{
 public:
  explicit rsa_exception(const std::string& msg) : std::runtime_error(msg) {}
};

// ------------------------ public_key ------------------------
class public_key
{
 public:
  explicit public_key(const std::string& pem);
  explicit public_key(std::istream& is);
  ~public_key();

  // 加密：固定使用 RSA-OAEP（内部 hash 算法固定为 OpenSSL 默认）
  std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) const;

  // 验证签名：固定使用 RSA-PSS + hash_alg
  bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature,
              rsa::hash hash_alg = rsa::hash::SHA256) const;

  std::string pem() const;

 private:
  RSA* rsa_ = nullptr;
};

// ------------------------ private_key ------------------------
class private_key
{
 public:
  explicit private_key(rsa::bits bits = rsa::bits::RSA_2048, const std::string& password = "");
  explicit private_key(const std::string& pem, const std::string& password = "");
  explicit private_key(std::istream& is, const std::string& password = "");
  ~private_key();

  // 解密：固定使用 RSA-OAEP（内部 hash 算法固定为 OpenSSL 默认）
  std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) const;

  // 签名：固定使用 RSA-PSS + hash_alg
  std::vector<unsigned char> sign(const std::vector<unsigned char>& message,
                                  rsa::hash hash_alg = rsa::hash::SHA256) const;

  std::string pem() const;         // 导出私钥 PEM，可加密
  std::string public_pem() const;  // 导出公钥 PEM

  public_key get_public() const;

  void set_password(const std::string& password);

 private:
  RSA* rsa_ = nullptr;
  std::string password_;
};

}  // namespace rsa
}  // namespace cryptx
