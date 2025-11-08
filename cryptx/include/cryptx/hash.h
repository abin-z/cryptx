#pragma once

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptx
{
namespace hash
{

class hash_exception : public std::runtime_error
{
 public:
  explicit hash_exception(const std::string& msg) : std::runtime_error(msg) {}
};

enum class alg
{
  MD5,
  SHA1,
  SHA224,
  SHA256,
  SHA384,
  SHA512
};

class hasher
{
 public:
  explicit hasher(hash::alg a);

  // 分块更新（链式）
  hasher& update(const void* data, std::size_t len);
  hasher& update(const std::vector<unsigned char>& data);

  std::vector<unsigned char> final_bin();
  std::string final_hex();

  ~hasher() = default;
  hasher(const hasher&) = delete;
  hasher& operator=(const hasher&) = delete;
  hasher(hasher&&) noexcept = default;
  hasher& operator=(hasher&&) noexcept = default;

 private:
  hash::alg alg_;
  bool finalized_;

  // 使用函数指针作为 unique_ptr 的删除器
  std::unique_ptr<void, void (*)(void*)> ctx_{nullptr, nullptr};

  using update_fn = int (*)(void*, const void*, size_t);
  using final_fn = int (*)(void*, unsigned char*);

  update_fn update_func_{nullptr};
  final_fn final_func_{nullptr};

  std::size_t digest_length() const;
};

// 一次性计算函数
std::vector<unsigned char> compute_bin(const std::string& data, hash::alg a = hash::alg::SHA256);
std::string compute(const std::string& data, hash::alg a = hash::alg::SHA256);

std::vector<unsigned char> compute_file_bin(const std::string& filepath, hash::alg a = hash::alg::SHA256);
std::string compute_file(const std::string& filepath, hash::alg a = hash::alg::SHA256);

}  // namespace hash
}  // namespace cryptx
