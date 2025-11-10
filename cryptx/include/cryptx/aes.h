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

// ----------------------------
// AES 模式
// ----------------------------
enum class mode
{
  CBC,  ///< 密码分组链接模式，常用，需填充
  CFB,  ///< 密文反馈模式，流式，可加密任意长度
  OFB,  ///< 输出反馈模式，流式，适用于连续数据流
  CTR   ///< 计数器模式，流式，现代推荐
};

// ----------------------------
// 填充模式
// ----------------------------
enum class padding_mode
{
  None,  ///< 不使用填充（适用于流模式）
  PKCS7  ///< 标准填充方式，安全且广泛支持
};

// ----------------------------
// AES 密钥长度（单位：字节）
// ----------------------------
enum class key_len
{
  AES_128 = 16,
  AES_192 = 24,
  AES_256 = 32
};

// ----------------------------
// AES 配置选项
// ----------------------------
struct options
{
  mode cipher_mode = mode::CBC;                 ///< AES 模式
  padding_mode pad_mode = padding_mode::PKCS7;  ///< 填充模式
  key_len key_bits = key_len::AES_256;          ///< 密钥长度
  std::vector<uint8_t> key;                     ///< 密钥，长度必须与 key_bits 匹配
  std::vector<uint8_t> iv;                      ///< 初始向量，长度固定 16 字节
};

// ----------------------------
// AES 异常类
// ----------------------------
class aes_exception : public std::runtime_error
{
 public:
  using std::runtime_error::runtime_error;
};

// ----------------------------
// AES 加解密类
// ----------------------------
class cipher
{
 public:
  /**
   * @brief 构造函数，初始化 AES 加解密上下文
   * @param opts AES 参数配置
   * @param encrypt true: 加密, false: 解密
   * @throws aes_exception 如果 key 或 iv 不合法
   */
  explicit cipher(const options& opts, bool encrypt);
  ~cipher() = default;

  cipher(const cipher&) = delete;
  cipher& operator=(const cipher&) = delete;
  cipher(cipher&&) noexcept = default;
  cipher& operator=(cipher&&) noexcept = default;

  /**
   * @brief 分块加解密
   * @param data 输入数据
   * @param len 数据长度
   * @return 当前块处理结果
   */
  std::vector<uint8_t> update(const uint8_t* data, std::size_t len);

  /**
   * @brief 完成加解密，返回最终结果（含填充处理）
   * @return 最终加解密数据
   */
  std::vector<uint8_t> final();

  /**
   * @brief 一次性加密
   * @param plaintext 明文
   * @param opts AES 配置
   * @return 密文
   */
  static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const options& opts);

  /**
   * @brief 一次性解密
   * @param ciphertext 密文
   * @param opts AES 配置
   * @return 明文
   */
  static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const options& opts);

  /**
   * @brief 生成随机密钥
   * @param len 密钥长度（默认 AES_256）
   * @return 随机密钥
   */
  static std::vector<uint8_t> random_key(key_len len);

  /**
   * @brief 生成随机 IV
   * @return 16 字节随机 IV
   */
  static std::vector<uint8_t> random_iv();

 private:
  const EVP_CIPHER* resolve_cipher() const;  ///< 获取 OpenSSL EVP_CIPHER 类型
  void init_context();                       ///< 初始化 EVP_CIPHER_CTX

 private:
  options opts_;                  ///< AES 配置
  bool encrypt_ = false;          ///< 是否加密
  bool finalized_ = false;        ///< 是否已完成加解密
  std::vector<uint8_t> out_buf_;  ///< 输出缓冲区
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
};

}  // namespace aes
}  // namespace cryptx
