#include "cryptx/hash.h"

#include <array>
#include <fstream>

namespace cryptx
{
namespace hash
{

namespace
{
constexpr std::size_t BUFFER_SIZE = 8192;
using Buffer = std::array<char, BUFFER_SIZE>;

// ---------------- 十六进制转换 ----------------
static std::string to_hex_string(const unsigned char* data, std::size_t len)
{
  static const char hex_chars[] = "0123456789abcdef";
  std::string s(len * 2, '0');
  for (size_t i = 0; i < len; ++i)
  {
    s[2 * i] = hex_chars[data[i] >> 4];
    s[2 * i + 1] = hex_chars[data[i] & 0xF];
  }
  return s;
}

// ---------------- update/final 函数 ----------------
int md5_update(void* ctx, const void* data, size_t len)
{
  return MD5_Update(static_cast<MD5_CTX*>(ctx), data, len);
}
int md5_final(void* ctx, unsigned char* digest)
{
  return MD5_Final(digest, static_cast<MD5_CTX*>(ctx));
}

int sha1_update(void* ctx, const void* data, size_t len)
{
  return SHA1_Update(static_cast<SHA_CTX*>(ctx), data, len);
}
int sha1_final(void* ctx, unsigned char* digest)
{
  return SHA1_Final(digest, static_cast<SHA_CTX*>(ctx));
}

int sha224_update(void* ctx, const void* data, size_t len)
{
  return SHA224_Update(static_cast<SHA256_CTX*>(ctx), data, len);
}
int sha224_final(void* ctx, unsigned char* digest)
{
  return SHA224_Final(digest, static_cast<SHA256_CTX*>(ctx));
}

int sha256_update(void* ctx, const void* data, size_t len)
{
  return SHA256_Update(static_cast<SHA256_CTX*>(ctx), data, len);
}
int sha256_final(void* ctx, unsigned char* digest)
{
  return SHA256_Final(digest, static_cast<SHA256_CTX*>(ctx));
}

int sha384_update(void* ctx, const void* data, size_t len)
{
  return SHA384_Update(static_cast<SHA512_CTX*>(ctx), data, len);
}
int sha384_final(void* ctx, unsigned char* digest)
{
  return SHA384_Final(digest, static_cast<SHA512_CTX*>(ctx));
}

int sha512_update(void* ctx, const void* data, size_t len)
{
  return SHA512_Update(static_cast<SHA512_CTX*>(ctx), data, len);
}
int sha512_final(void* ctx, unsigned char* digest)
{
  return SHA512_Final(digest, static_cast<SHA512_CTX*>(ctx));
}

// ---------------- 删除器 ----------------
void delete_md5_ctx(void* p)
{
  delete static_cast<MD5_CTX*>(p);
}
void delete_sha1_ctx(void* p)
{
  delete static_cast<SHA_CTX*>(p);
}
void delete_sha224_ctx(void* p)
{
  delete static_cast<SHA256_CTX*>(p);
}
void delete_sha256_ctx(void* p)
{
  delete static_cast<SHA256_CTX*>(p);
}
void delete_sha384_ctx(void* p)
{
  delete static_cast<SHA512_CTX*>(p);
}
void delete_sha512_ctx(void* p)
{
  delete static_cast<SHA512_CTX*>(p);
}

}  // namespace

// ---------------- hasher ----------------
hasher::hasher(hash::alg a) : alg_(a), finalized_(false)
{
  switch (alg_)
  {
  case alg::MD5: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new MD5_CTX, &delete_md5_ctx);
    if (MD5_Init(static_cast<MD5_CTX*>(ptr.get())) != 1) throw hash_exception("MD5_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &md5_update;
    final_func_ = &md5_final;
    break;
  }
  case alg::SHA1: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new SHA_CTX, &delete_sha1_ctx);
    if (SHA1_Init(static_cast<SHA_CTX*>(ptr.get())) != 1) throw hash_exception("SHA1_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &sha1_update;
    final_func_ = &sha1_final;
    break;
  }
  case alg::SHA224: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new SHA256_CTX, &delete_sha224_ctx);
    if (SHA224_Init(static_cast<SHA256_CTX*>(ptr.get())) != 1) throw hash_exception("SHA224_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &sha224_update;
    final_func_ = &sha224_final;
    break;
  }
  case alg::SHA256: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new SHA256_CTX, &delete_sha256_ctx);
    if (SHA256_Init(static_cast<SHA256_CTX*>(ptr.get())) != 1) throw hash_exception("SHA256_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &sha256_update;
    final_func_ = &sha256_final;
    break;
  }
  case alg::SHA384: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new SHA512_CTX, &delete_sha384_ctx);
    if (SHA384_Init(static_cast<SHA512_CTX*>(ptr.get())) != 1) throw hash_exception("SHA384_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &sha384_update;
    final_func_ = &sha384_final;
    break;
  }
  case alg::SHA512: {
    auto ptr = std::unique_ptr<void, void (*)(void*)>(new SHA512_CTX, &delete_sha512_ctx);
    if (SHA512_Init(static_cast<SHA512_CTX*>(ptr.get())) != 1) throw hash_exception("SHA512_Init failed");
    ctx_ = std::move(ptr);
    update_func_ = &sha512_update;
    final_func_ = &sha512_final;
    break;
  }
  default:
    throw hash_exception("Unsupported hash algorithm");
  }
}

hasher& hasher::update(const void* data, std::size_t len)
{
  if (finalized_) throw hash_exception("Hasher already finalized");
  if (!data || len == 0) return *this;
  if (update_func_(ctx_.get(), data, len) != 1) throw hash_exception("Update failed");
  return *this;
}

hasher& hasher::update(const std::vector<unsigned char>& data)
{
  return update(data.data(), data.size());
}

std::size_t hasher::digest_length() const
{
  switch (alg_)
  {
  case alg::MD5:
    return MD5_DIGEST_LENGTH;
  case alg::SHA1:
    return SHA_DIGEST_LENGTH;
  case alg::SHA224:
    return SHA224_DIGEST_LENGTH;
  case alg::SHA256:
    return SHA256_DIGEST_LENGTH;
  case alg::SHA384:
    return SHA384_DIGEST_LENGTH;
  case alg::SHA512:
    return SHA512_DIGEST_LENGTH;
  default:
    throw hash_exception("Unsupported algorithm");
  }
}

std::vector<unsigned char> hasher::final_bin()
{
  if (finalized_) throw hash_exception("Already finalized");
  std::vector<unsigned char> digest(digest_length());
  if (final_func_(ctx_.get(), digest.data()) != 1) throw hash_exception("Final failed");
  finalized_ = true;
  return digest;
}

std::string hasher::final_hex()
{
  auto d = final_bin();
  return to_hex_string(d.data(), d.size());
}

// ------------------------ 一次性计算函数 ------------------------
std::vector<unsigned char> compute_bin(const std::string& data, hash::alg a)
{
  return hasher(a).update(data.data(), data.size()).final_bin();
}

std::string compute(const std::string& data, hash::alg a)
{
  return hasher(a).update(data.data(), data.size()).final_hex();
}

std::vector<unsigned char> compute_file_bin(const std::string& filepath, hash::alg a)
{
  std::ifstream file(filepath, std::ios::binary);
  if (!file) throw hash_exception("Failed to open file: " + filepath);

  Buffer buffer;
  hasher h(a);
  while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0)
  {
    h.update(buffer.data(), file.gcount());
  }
  return h.final_bin();
}

std::string compute_file(const std::string& filepath, hash::alg a)
{
  auto d = compute_file_bin(filepath, a);
  return to_hex_string(d.data(), d.size());
}

}  // namespace hash
}  // namespace cryptx
