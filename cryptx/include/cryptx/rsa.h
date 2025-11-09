// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Abin

/**
 * @file rsa.h
 * @brief: RSA 非对称加密算法封装
 * @author: abin
 * @date: 2025-11-07
 */

#pragma once

// 定义宏，让高版本 OpenSSL 不触发弃用警告
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <istream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptx
{
namespace rsa
{

// ------------------------ 枚举类型 ------------------------

// RSA 密钥长度
enum class bits
{
  RSA_1024 = 1024,
  RSA_2048 = 2048,
  RSA_3072 = 3072,
  RSA_4096 = 4096
};

// OAEP 加密解密时可选的哈希算法
enum class oaep_hash
{
  SHA1,    // 向下兼容旧接口
  SHA256,  // 现代推荐，默认值
  SHA384,  // 可选，高安全要求
  SHA512   // 可选，最高安全要求
};

// PSS 签名和验签可选的哈希算法
enum class hash
{
  SHA256,  // 默认
  SHA512
};

// 私钥 PEM 导出格式
enum class pem_format
{
  PKCS1,  // "BEGIN RSA PRIVATE KEY"
  PKCS8   // "BEGIN PRIVATE KEY" 或 "BEGIN ENCRYPTED PRIVATE KEY"
};

// ------------------------ 异常类 ------------------------

// RSA 相关异常
class rsa_exception : public std::runtime_error
{
 public:
  explicit rsa_exception(const std::string& msg) : std::runtime_error(msg) {}
};

// ------------------------ 公钥类 ------------------------
class public_key
{
 public:
  // 构造函数：从 PEM 字符串加载公钥
  explicit public_key(const std::string& pem);

  // 构造函数：从输入流加载公钥
  explicit public_key(std::istream& is);

  // 移动构造和赋值
  public_key(public_key&&) noexcept = default;
  public_key& operator=(public_key&&) noexcept = default;

  // 禁止拷贝
  public_key(const public_key&) = delete;
  public_key& operator=(const public_key&) = delete;

  ~public_key() = default;  // unique_ptr 会自动释放

  /**
   * @brief 公钥加密
   * @param plaintext 待加密数据
   * @param hash_alg OAEP 哈希算法（默认 SHA256）
   * @return 加密后的数据
   * @note 固定使用 OAEP 填充
   */
  std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                     oaep_hash hash_alg = oaep_hash::SHA256) const;

  /**
   * @brief 验签
   * @param message 原始消息
   * @param signature 签名数据
   * @param hash_alg PSS 哈希算法（默认 SHA256）
   * @return 是否验证通过
   */
  bool verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature,
              hash hash_alg = hash::SHA256) const;

  /**
   * @brief 导出公钥 PEM
   * @return PEM 格式字符串
   */
  std::string pem() const;

 private:
  std::unique_ptr<RSA, decltype(&RSA_free)> rsa_{nullptr, &RSA_free};
};

// ------------------------ 私钥类 ------------------------
class private_key
{
 public:
  /**
   * @brief 生成新的私钥
   * @param bits 密钥长度
   * @param password 用于 PEM 加密的密码（可空，表示明文 PEM）
   */
  explicit private_key(bits bits = bits::RSA_2048, const std::string& password = "");

  /**
   * @brief 从 PEM 字符串加载私钥
   * @param pem PEM 格式私钥
   * @param password 私钥密码（若 PEM 已加密）
   */
  explicit private_key(const std::string& pem, const std::string& password = "");

  /**
   * @brief 从输入流加载私钥
   * @param is 输入流
   * @param password 私钥密码
   */
  explicit private_key(std::istream& is, const std::string& password = "");

  // 移动构造和赋值
  private_key(private_key&&) noexcept = default;
  private_key& operator=(private_key&&) noexcept = default;

  // 禁止拷贝
  private_key(const private_key&) = delete;
  private_key& operator=(const private_key&) = delete;

  ~private_key() = default;  // unique_ptr 会自动释放

  /**
   * @brief 私钥解密
   * @param ciphertext 待解密数据
   * @param hash_alg OAEP 哈希算法（默认 SHA256）
   * @return 解密后的明文
   */
  std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                     oaep_hash hash_alg = oaep_hash::SHA256) const;

  /**
   * @brief 签名
   * @param message 待签名消息
   * @param hash_alg PSS 哈希算法（默认 SHA256）
   * @return 签名数据
   */
  std::vector<unsigned char> sign(const std::vector<unsigned char>& message, hash hash_alg = hash::SHA256) const;

  /**
   * @brief 导出私钥 PEM
   * @param fmt PEM 格式（PKCS1 或 PKCS8）
   * @return PEM 字符串
   * @note 是否加密由 password_ 决定
   */
  std::string pem(pem_format fmt = pem_format::PKCS8) const;

  /**
   * @brief 导出公钥 PEM
   * @return 公钥 PEM 字符串
   */
  std::string public_pem() const;

  /**
   * @brief 获取公钥对象
   * @return 对应的 public_key
   */
  public_key get_public() const;

  /**
   * @brief 设置私钥 PEM 加密密码
   * @param password 密码
   */
  void set_password(const std::string& password);

 private:
  std::unique_ptr<RSA, decltype(&RSA_free)> rsa_{nullptr, &RSA_free};  // 底层 OpenSSL RSA 对象
  std::string password_;                                               // PEM 导出加密密码
};

}  // namespace rsa
}  // namespace cryptx
