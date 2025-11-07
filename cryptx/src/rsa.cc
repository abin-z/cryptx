#include "cryptx/rsa.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstring>
#include <sstream>

namespace cryptx
{
namespace rsa
{

// ------------------------ public_key ------------------------

public_key::public_key(const std::string& pem) : rsa_(nullptr)
{
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) throw rsa_exception("BIO allocation failed");

  rsa_ = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
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

public_key::~public_key()
{
  if (rsa_) RSA_free(rsa_);
}

// 固定使用 RSA-OAEP（内部默认 SHA1）
std::vector<unsigned char> public_key::encrypt(const std::vector<unsigned char>& plaintext) const
{
  if (!rsa_) throw rsa_exception("RSA public key not initialized");

  int rsa_size = RSA_size(rsa_);
  std::vector<unsigned char> out(rsa_size);

  int len =
    RSA_public_encrypt(static_cast<int>(plaintext.size()), plaintext.data(), out.data(), rsa_, RSA_PKCS1_OAEP_PADDING);

  if (len < 0) throw rsa_exception("RSA encryption failed");

  out.resize(len);
  return out;
}

bool public_key::verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature,
                        rsa::hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA public key not initialized");

  const EVP_MD* md = (hash_alg == hash::SHA512) ? EVP_sha512() : EVP_sha256();

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_) != 1)
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

  if (!PEM_write_bio_RSA_PUBKEY(bio, rsa_))
  {
    BIO_free(bio);
    throw rsa_exception("Failed to write RSA public key PEM");
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem(data, len);
  BIO_free(bio);
  return pem;
}

// ------------------------ private_key ------------------------

private_key::private_key(rsa::bits bits, const std::string& password) : rsa_(nullptr), password_(password)
{
  rsa_ = RSA_new();
  BIGNUM* e = BN_new();
  BN_set_word(e, RSA_F4);

  if (!RSA_generate_key_ex(rsa_, static_cast<int>(bits), e, nullptr))
  {
    BN_free(e);
    RSA_free(rsa_);
    throw rsa_exception("RSA key generation failed");
  }

  BN_free(e);
}

private_key::private_key(const std::string& pem, const std::string& password) : rsa_(nullptr), password_(password)
{
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  if (!bio) throw rsa_exception("BIO allocation failed");

  rsa_ = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, password.empty() ? nullptr : (void*)password.c_str());
  BIO_free(bio);

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

private_key::~private_key()
{
  if (rsa_) RSA_free(rsa_);
}

// 固定使用 RSA-OAEP（内部默认 SHA1）
std::vector<unsigned char> private_key::decrypt(const std::vector<unsigned char>& ciphertext) const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  int rsa_size = RSA_size(rsa_);
  std::vector<unsigned char> out(rsa_size);

  int len = RSA_private_decrypt(static_cast<int>(ciphertext.size()), ciphertext.data(), out.data(), rsa_,
                                RSA_PKCS1_OAEP_PADDING);

  if (len < 0) throw rsa_exception("RSA decryption failed");

  out.resize(len);
  return out;
}

std::vector<unsigned char> private_key::sign(const std::vector<unsigned char>& message, rsa::hash hash_alg) const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  const EVP_MD* md = (hash_alg == hash::SHA512) ? EVP_sha512() : EVP_sha256();

  EVP_PKEY* pkey = EVP_PKEY_new();
  if (!pkey) throw rsa_exception("EVP_PKEY allocation failed");
  if (EVP_PKEY_set1_RSA(pkey, rsa_) != 1)
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

std::string private_key::pem() const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) throw rsa_exception("BIO allocation failed");

  if (!PEM_write_bio_RSAPrivateKey(bio, rsa_, password_.empty() ? nullptr : EVP_aes_256_cbc(), nullptr, 0, nullptr,
                                   password_.empty() ? nullptr : (void*)password_.c_str()))
  {
    BIO_free(bio);
    throw rsa_exception("Failed to write RSA private key PEM");
  }

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem(data, len);
  BIO_free(bio);
  return pem;
}

std::string private_key::public_pem() const
{
  return get_public().pem();
}

public_key private_key::get_public() const
{
  if (!rsa_) throw rsa_exception("RSA private key not initialized");

  RSA* rsa_pub = RSAPublicKey_dup(rsa_);
  if (!rsa_pub) throw rsa_exception("Failed to duplicate RSA public key");

  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSA_PUBKEY(bio, rsa_pub);
  RSA_free(rsa_pub);

  char* data = nullptr;
  long len = BIO_get_mem_data(bio, &data);
  std::string pem(data, len);
  BIO_free(bio);

  return public_key(pem);
}

void private_key::set_password(const std::string& password)
{
  password_ = password;
}

}  // namespace rsa
}  // namespace cryptx
