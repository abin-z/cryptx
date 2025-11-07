#include "cryptx/rsa.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <cstring>
#include <sstream>

namespace cryptx
{
namespace rsa
{

namespace
{
const EVP_MD* get_oaep_md(cryptx::rsa::oaep_hash hash_alg)
{
  switch (hash_alg)
  {
  case cryptx::rsa::oaep_hash::SHA1:
    return EVP_sha1();
  case cryptx::rsa::oaep_hash::SHA256:
    return EVP_sha256();
  case cryptx::rsa::oaep_hash::SHA384:
    return EVP_sha384();
  case cryptx::rsa::oaep_hash::SHA512:
    return EVP_sha512();
  default:
    throw cryptx::rsa::rsa_exception("Unsupported OAEP hash algorithm");
  }
}
}  // namespace

// ------------------------ public_key ------------------------

public_key::public_key(const std::string& pem)
{
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) throw rsa_exception("BIO allocation failed");

  rsa_.reset(PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr));
  BIO_free(bio);

  if (!rsa_) throw rsa_exception("Failed to load RSA public key");
}

public_key::public_key(std::istream& is) :
  public_key([&]() {
    std::ostringstream oss;
    oss << is.rdbuf();
    return oss.str();
  }())
{
}

// 公钥加密 OAEP，可选 hash
std::vector<unsigned char> public_key::encrypt(const std::vector<unsigned char>& plaintext, oaep_hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA public key not initialized");

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_.get()) != 1)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_set1_RSA failed");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_CTX allocation failed");
  }

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_encrypt_init failed");
  }

  // 设置 OAEP padding
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("Failed to set OAEP padding");
  }

  // 设置 OAEP hash
  const EVP_MD* md = get_oaep_md(hash_alg);

  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("Failed to set OAEP hash");
  }

  size_t outlen = 0;
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_encrypt size query failed");
  }

  std::vector<unsigned char> out(outlen);
  if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, plaintext.data(), plaintext.size()) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_encrypt failed");
  }
  out.resize(outlen);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return out;
}

// 验签 PSS
bool public_key::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature,
                        hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA public key not initialized");

  const EVP_MD* md = (hash_alg == hash::SHA512) ? EVP_sha512() : EVP_sha256();

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_.get()) != 1)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_set1_RSA failed");
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_MD_CTX allocation failed");
  }

  bool ok = false;
  EVP_PKEY_CTX* pkctx = nullptr;
  if (EVP_DigestVerifyInit(ctx, &pkctx, md, nullptr, pkey) == 1)
  {
    EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, -1);

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) == 1)
    {
      if (EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1)
      {
        ok = true;
      }
    }
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

std::string public_key::pem() const
{
  if (!rsa_) throw rsa_exception("RSA public key not initialized");

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) throw rsa_exception("BIO allocation failed");

  if (!PEM_write_bio_RSA_PUBKEY(bio, rsa_.get()))
  {
    BIO_free(bio);
    throw rsa_exception("Failed to write RSA public key PEM");
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem_str(data, len);
  BIO_free(bio);
  return pem_str;
}

// ------------------------ private_key ------------------------

private_key::private_key(bits bits, const std::string& password) :
  rsa_(RSA_new(), &RSA_free), password_(password)  // 初始化 unique_ptr
{
  if (!rsa_) throw rsa_exception("RSA allocation failed");

  BIGNUM* e = BN_new();
  if (!e) throw rsa_exception("BIGNUM allocation failed");
  BN_set_word(e, RSA_F4);

  if (!RSA_generate_key_ex(rsa_.get(), static_cast<int>(bits), e, nullptr))
  {
    BN_free(e);
    throw rsa_exception("RSA key generation failed");
  }

  BN_free(e);
}

private_key::private_key(const std::string& pem, const std::string& password) : password_(password)
{
  if (pem.empty()) throw rsa_exception("Empty PEM string");

  // 用 unique_ptr 管理 BIO，异常安全
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);

  if (!bio) throw rsa_exception("BIO allocation failed");

  // 读取私钥
  rsa_.reset(
    PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, password.empty() ? nullptr : (void*)password.c_str()));

  if (!rsa_) throw rsa_exception("Failed to load RSA private key");
}

private_key::private_key(std::istream& is, const std::string& password) :
  private_key(
    [&]() {
      std::ostringstream oss;
      oss << is.rdbuf();
      return oss.str();
    }(),
    password)
{
}

// 私钥解密 OAEP
std::vector<unsigned char> private_key::decrypt(const std::vector<unsigned char>& ciphertext, oaep_hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_.get()) != 1)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_set1_RSA failed");
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  if (!ctx)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_CTX allocation failed");
  }

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_decrypt_init failed");
  }

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("Failed to set OAEP padding");
  }

  const EVP_MD* md = get_oaep_md(hash_alg);

  if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) <= 0 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("Failed to set OAEP hash");
  }

  size_t outlen = 0;
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_decrypt size query failed");
  }

  std::vector<unsigned char> out(outlen);
  if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_decrypt failed");
  }
  out.resize(outlen);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return out;
}

// 签名 PSS
std::vector<unsigned char> private_key::sign(const std::vector<unsigned char>& message, hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  const EVP_MD* md = (hash_alg == hash::SHA512) ? EVP_sha512() : EVP_sha256();

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_.get()) != 1)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_PKEY_set1_RSA failed");
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx)
  {
    EVP_PKEY_free(pkey);
    throw rsa_exception("EVP_MD_CTX allocation failed");
  }

  std::vector<unsigned char> sig(EVP_PKEY_size(pkey));
  size_t sig_len = sig.size();

  EVP_PKEY_CTX* pkctx = nullptr;
  if (EVP_DigestSignInit(ctx, &pkctx, md, nullptr, pkey) != 1)
  {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("DigestSignInit failed");
  }

  EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING);
  EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, -1);

  if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1 ||
      EVP_DigestSignFinal(ctx, sig.data(), &sig_len) != 1)
  {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw rsa_exception("Sign failed");
  }

  sig.resize(sig_len);
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return sig;
}

// ------------------------ PEM 导出 ------------------------

std::string private_key::pem(pem_format fmt) const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) throw rsa_exception("BIO allocation failed");

  if (fmt == pem_format::PKCS1)
  {
    if (!PEM_write_bio_RSAPrivateKey(bio, rsa_.get(), password_.empty() ? nullptr : EVP_aes_256_cbc(), nullptr, 0, nullptr,
                                     password_.empty() ? nullptr : (void*)password_.c_str()))
    {
      BIO_free(bio);
      throw rsa_exception("Failed to write PKCS1 private key PEM");
    }
  }
  else  // PKCS8
  {
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey)
    {
      BIO_free(bio);
      throw rsa_exception("EVP_PKEY allocation failed");
    }
    if (EVP_PKEY_set1_RSA(pkey, rsa_.get()) != 1)
    {
      EVP_PKEY_free(pkey);
      BIO_free(bio);
      throw rsa_exception("EVP_PKEY_set1_RSA failed");
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, password_.empty() ? nullptr : EVP_aes_256_cbc(), nullptr, 0, nullptr,
                                  password_.empty() ? nullptr : (void*)password_.c_str()))
    {
      EVP_PKEY_free(pkey);
      BIO_free(bio);
      throw rsa_exception("Failed to write PKCS8 private key PEM");
    }
    EVP_PKEY_free(pkey);
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem_str(data, len);
  BIO_free(bio);
  return pem_str;
}

std::string private_key::public_pem() const
{
  return get_public().pem();
}

public_key private_key::get_public() const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  RSA* rsa_pub = RSAPublicKey_dup(rsa_.get());
  if (!rsa_pub) throw rsa_exception("Failed to duplicate RSA public key");

  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(bio, rsa_pub);
  RSA_free(rsa_pub);

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem_str(data, len);
  BIO_free(bio);

  return public_key(pem_str);
}

void private_key::set_password(const std::string& password)
{
  password_ = password;
}

}  // namespace rsa
}  // namespace cryptx
