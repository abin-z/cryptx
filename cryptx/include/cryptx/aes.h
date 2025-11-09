// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Abin

/**
 * @file aes.h
 * @description: AES 对称加密算法封装（现代常用模式）
 * @author: abin
 * @date: 2025-11-09
 */

#pragma once

#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace cryptx
{
namespace aes
{

// 现代常用 AES 模式
enum class mode
{
  CBC,
  CFB,
  OFB,
  CTR
};

// 常用填充模式
enum class padding_mode
{
  None,
  PKCS7
};

// AES 密钥长度（字节）
enum class key_len
{
  AES_128 = 16,
  AES_192 = 24,
  AES_256 = 32
};

// AES 参数配置
struct options
{
  mode cipher_mode = mode::CBC;
  padding_mode pad_mode = padding_mode::PKCS7;
  key_len key_bits = key_len::AES_256;
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;  // CBC 模式等必须提供
};

// AES 异常
class aes_exception : public std::runtime_error
{
 public:
  using std::runtime_error::runtime_error;
};

// AES 加解密类
class cipher
{
 public:
  explicit cipher(const options& opts, bool encrypt);
  ~cipher() = default;

  cipher(const cipher&) = delete;
  cipher& operator=(const cipher&) = delete;

  cipher(cipher&&) noexcept = default;
  cipher& operator=(cipher&&) noexcept = default;

  std::vector<uint8_t> update(const uint8_t* data, std::size_t len);
  std::vector<uint8_t> final();

  static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const options& opts);
  static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const options& opts);

  static std::vector<uint8_t> random_key(key_len len = key_len::AES_256);
  static std::vector<uint8_t> random_iv();

 private:
  const EVP_CIPHER* resolve_cipher() const;
  void init_context();

 private:
  options opts_;
  bool encrypt_ = false;
  bool finalized_ = false;
  std::vector<uint8_t> out_buf_;
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
};

}  // namespace aes
}  // namespace cryptx
