#include "cryptx/aes.h"

namespace cryptx
{
namespace aes
{

cipher::cipher(const options& opts, bool encrypt) : opts_(opts), encrypt_(encrypt)
{
  if (opts_.key.empty()) throw aes_exception("AES key must not be empty");
  // 检查 key 长度是否和 key_bits 匹配
  if (opts_.key.size() != static_cast<std::size_t>(opts_.key_bits))
    throw aes_exception("AES key length mismatch with key_bits");
  if (opts_.iv.empty() && opts_.cipher_mode != mode::CTR && opts_.cipher_mode != mode::OFB &&
      opts_.cipher_mode != mode::CFB)
    throw aes_exception("IV must be provided for this AES mode");

  init_context();
}

void cipher::init_context()
{
  const EVP_CIPHER* cipher_type = resolve_cipher();
  if (!cipher_type) throw aes_exception("Unsupported AES mode or key length");

  if (EVP_CipherInit_ex(ctx_.get(), cipher_type, nullptr, nullptr, nullptr, encrypt_ ? 1 : 0) != 1)
    throw aes_exception("EVP_CipherInit_ex failed");

  EVP_CIPHER_CTX_set_padding(ctx_.get(), opts_.pad_mode == padding_mode::PKCS7 ? 1 : 0);

  if (EVP_CipherInit_ex(ctx_.get(), nullptr, nullptr, opts_.key.data(), opts_.iv.empty() ? nullptr : opts_.iv.data(),
                        -1) != 1)
    throw aes_exception("EVP_CipherInit_ex key/iv failed");
}

std::vector<uint8_t> cipher::update(const uint8_t* data, std::size_t len)
{
  if (finalized_) throw aes_exception("cipher already finalized");

  std::vector<uint8_t> out(len + EVP_CIPHER_CTX_block_size(ctx_.get()));
  int out_len = 0;

  if (EVP_CipherUpdate(ctx_.get(), out.data(), &out_len, data, static_cast<int>(len)) != 1)
    throw aes_exception("EVP_CipherUpdate failed");

  out.resize(out_len);
  return out;
}

std::vector<uint8_t> cipher::final()
{
  if (finalized_) throw aes_exception("cipher already finalized");

  std::vector<uint8_t> out(EVP_CIPHER_CTX_block_size(ctx_.get()));
  int out_len = 0;

  if (EVP_CipherFinal_ex(ctx_.get(), out.data(), &out_len) != 1) throw aes_exception("EVP_CipherFinal_ex failed");

  out.resize(out_len);
  finalized_ = true;
  return out;
}

std::vector<uint8_t> cipher::encrypt(const std::vector<uint8_t>& plaintext, const options& opts)
{
  cipher c(opts, true);
  auto out1 = c.update(plaintext.data(), plaintext.size());
  auto out2 = c.final();
  out1.insert(out1.end(), out2.begin(), out2.end());
  return out1;
}

std::vector<uint8_t> cipher::decrypt(const std::vector<uint8_t>& ciphertext, const options& opts)
{
  cipher c(opts, false);
  auto out1 = c.update(ciphertext.data(), ciphertext.size());
  auto out2 = c.final();
  out1.insert(out1.end(), out2.begin(), out2.end());
  return out1;
}

const EVP_CIPHER* cipher::resolve_cipher() const
{
  const auto key_size = static_cast<int>(opts_.key_bits);

  switch (opts_.cipher_mode)
  {
  case mode::CBC:
    switch (key_size)
    {
    case 16:
      return EVP_aes_128_cbc();
    case 24:
      return EVP_aes_192_cbc();
    case 32:
      return EVP_aes_256_cbc();
    }
    break;
  case mode::CFB:
    switch (key_size)
    {
    case 16:
      return EVP_aes_128_cfb128();
    case 24:
      return EVP_aes_192_cfb128();
    case 32:
      return EVP_aes_256_cfb128();
    }
    break;
  case mode::OFB:
    switch (key_size)
    {
    case 16:
      return EVP_aes_128_ofb();
    case 24:
      return EVP_aes_192_ofb();
    case 32:
      return EVP_aes_256_ofb();
    }
    break;
  case mode::CTR:
    switch (key_size)
    {
    case 16:
      return EVP_aes_128_ctr();
    case 24:
      return EVP_aes_192_ctr();
    case 32:
      return EVP_aes_256_ctr();
    }
    break;
  }
  return nullptr;
}

std::vector<uint8_t> cipher::random_key(key_len len)
{
  std::vector<uint8_t> key(static_cast<std::size_t>(len));
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) throw aes_exception("RAND_bytes failed");
  return key;
}

std::vector<uint8_t> cipher::random_iv()
{
  std::vector<uint8_t> iv(16);  // AES block size fixed 16 bytes
  if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) throw aes_exception("RAND_bytes failed");
  return iv;
}

}  // namespace aes
}  // namespace cryptx
