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

// 支持 OAEP 哈希选项
enum class oaep_hash
{
  SHA1,    // 老接口兼容
  SHA256,  // 现代推荐
  SHA384,  // 可选
  SHA512   // 高安全要求
};

// hash 枚举保留，用于指定 PSS/OAEP 哈希算法
enum class hash
{
  SHA256,
  SHA512
};

// PEM 导出格式
enum class pem_format
{
  PKCS1,  // BEGIN RSA PRIVATE KEY
  PKCS8   // BEGIN PRIVATE KEY / ENCRYPTED PRIVATE KEY
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

  // 加密：固定使用 OAEP，hash 可选（默认 SHA256）
  std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                     oaep_hash hash_alg = oaep_hash::SHA256) const;

  // 验签：固定 PSS，hash 可选（默认 SHA256）
  bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature,
              hash hash_alg = hash::SHA256) const;

  std::string pem() const;

 private:
  RSA* rsa_ = nullptr;
};

// ------------------------ private_key ------------------------
class private_key
{
 public:
  explicit private_key(bits bits = bits::RSA_2048, const std::string& password = "");
  explicit private_key(const std::string& pem, const std::string& password = "");
  explicit private_key(std::istream& is, const std::string& password = "");
  ~private_key();

  // 解密：固定 OAEP，可选择 hash（默认 SHA256）
  std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                     oaep_hash hash_alg = oaep_hash::SHA256) const;

  // 签名：固定 PSS，hash 可选
  std::vector<unsigned char> sign(const std::vector<unsigned char>& message, hash hash_alg = hash::SHA256) const;

  // 导出 PEM：是否加密由 password_ 决定
  std::string pem(pem_format fmt = pem_format::PKCS8) const;
  std::string public_pem() const;
  public_key get_public() const;
  void set_password(const std::string& password);

 private:
  RSA* rsa_ = nullptr;
  std::string password_;  // 用于加密私钥 PEM 导出
};

}  // namespace rsa
}  // namespace cryptx
