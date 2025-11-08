#include "cryptx/rsa.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <cstring>
#include <memory>
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
  /*
   * 使用 std::unique_ptr 管理 OpenSSL 资源的原因：
   *
   * 1. 自动释放（RAII）
   *    - 智能指针会在超出作用域时自动调用释放函数（如 RSA_free、EVP_PKEY_free 等），
   *      避免手动释放遗漏导致的内存泄漏。
   *
   * 2. 异常安全
   *    - 即使函数中途抛出异常，智能指针也会保证资源被释放，不需要在每个异常分支重复写 free。
   *
   * 3. 防止 double free
   *    - 智能指针只会释放一次底层资源，避免重复释放导致程序崩溃。
   *
   * 4. 可读性与可维护性
   *    - 省去大量重复的释放代码，代码更简洁、清晰。
   *
   * 5. 现代 C++ 风格
   *    - 符合 C++11 RAII 风格，安全、高效、易于维护。
   *
   * 示例：
   *   std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), &RSA_free);
   *   std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(data, len), &BIO_free);
   */
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free);
  if (!bio) throw rsa_exception("BIO allocation failed");
  rsa_.reset(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
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

  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio) throw rsa_exception("BIO allocation failed");

  if (!PEM_write_bio_RSA_PUBKEY(bio.get(), rsa_.get()))
  {
    throw rsa_exception("Failed to write RSA public key PEM");
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio.get(), &data);
  std::string pem_str(data, len);
  return pem_str;
}

// ------------------------ private_key ------------------------

private_key::private_key(bits bits, const std::string& password) :
  rsa_(RSA_new(), &RSA_free), password_(password)  // 初始化 unique_ptr
{
  if (!rsa_) throw rsa_exception("RSA allocation failed");
  // 使用 unique_ptr 管理 BIGNUM
  std::unique_ptr<BIGNUM, decltype(&BN_free)> e(BN_new(), &BN_free);
  if (!e) throw rsa_exception("BIGNUM allocation failed");

  BN_set_word(e.get(), RSA_F4);
  if (!RSA_generate_key_ex(rsa_.get(), static_cast<int>(bits), e.get(), nullptr))
  {
    throw rsa_exception("RSA key generation failed");
  }
}

private_key::private_key(const std::string& pem, const std::string& password) : password_(password)
{
  if (pem.empty()) throw rsa_exception("Empty PEM string");
  // 用 unique_ptr 管理 BIO
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

  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio) throw rsa_exception("BIO allocation failed");

  const EVP_CIPHER* cipher = password_.empty() ? nullptr : EVP_aes_256_cbc();
  void* pwd = password_.empty() ? nullptr : (void*)password_.c_str();

  if (fmt == pem_format::PKCS1)
  {
    if (!PEM_write_bio_RSAPrivateKey(bio.get(), rsa_.get(), cipher, nullptr, 0, nullptr, pwd))
      throw rsa_exception("Failed to write PKCS1 private key PEM");
  }
  else  // PKCS8
  {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), &EVP_PKEY_free);
    if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");

    if (EVP_PKEY_set1_RSA(pkey.get(), rsa_.get()) != 1) throw rsa_exception("EVP_PKEY_set1_RSA failed");

    if (!PEM_write_bio_PrivateKey(bio.get(), pkey.get(), cipher, nullptr, 0, nullptr, pwd))
      throw rsa_exception("Failed to write PKCS8 private key PEM");
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio.get(), &data);
  return std::string(data, len);
}

std::string private_key::public_pem() const
{
  return get_public().pem();
}

public_key private_key::get_public() const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  // 用 unique_ptr 管理 rsa_pub
  std::unique_ptr<RSA, decltype(&RSA_free)> rsa_pub(RSAPublicKey_dup(rsa_.get()), &RSA_free);
  if (!rsa_pub) throw rsa_exception("Failed to duplicate RSA public key");

  // 用 unique_ptr 管理 BIO
  std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), &BIO_free);
  if (!bio) throw rsa_exception("BIO allocation failed");

  if (!PEM_write_bio_RSA_PUBKEY(bio.get(), rsa_pub.get())) throw rsa_exception("Failed to write RSA public key PEM");

  char* data = nullptr;
  long len = BIO_get_mem_data(bio.get(), &data);
  std::string pem_str(data, len);

  return public_key(pem_str);
}

void private_key::set_password(const std::string& password)
{
  password_ = password;
}

}  // namespace rsa
}  // namespace cryptx
