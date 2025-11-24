// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Abin

/**
 * @file hash.h
 * @brief: 常用 hash 算法封装(MD5、SHA1、SHA224、SHA256、SHA384、SHA512)
 * @author: abin
 * @date: 2025-11-08
 */

#ifndef __GUARD_HASH_H_INCLUDE_GUARD__
#define __GUARD_HASH_H_INCLUDE_GUARD__

// 定义宏，让高版本 OpenSSL 不触发弃用警告
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

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

/**
 * @class hash_exception
 * @brief hash 操作异常类
 */
class hash_exception : public std::runtime_error
{
 public:
  explicit hash_exception(const std::string& msg) : std::runtime_error(msg) {}
};

/**
 * @enum alg
 * @brief 支持的 hash 算法类型
 */
enum class alg
{
  MD5,     ///< MD5
  SHA1,    ///< SHA1
  SHA224,  ///< SHA224
  SHA256,  ///< SHA256
  SHA384,  ///< SHA384
  SHA512   ///< SHA512
};

/**
 * @class hasher
 * @brief hash 计算器类
 *
 * 支持分块更新数据，并在最后获取摘要。
 * 一旦调用 final_bin() 或 final_hex()，对象标记为 finalized，不可再 update。
 */
class hasher
{
 public:
  /**
   * @brief 构造函数，初始化指定算法
   * @param a hash 算法类型
   * @throw hash_exception 如果算法初始化失败
   */
  explicit hasher(hash::alg a);

  /**
   * @brief 分块更新数据
   * @param data 数据指针
   * @param len 数据长度
   * @return 当前 hasher 引用，支持链式调用
   * @throw hash_exception 如果对象已 finalized
   */
  hasher& update(const void* data, std::size_t len);

  /**
   * @brief 分块更新数据（vector 版本）
   * @param data 数据 vector
   * @return 当前 hasher 引用，支持链式调用
   * @throw hash_exception 如果对象已 finalized
   */
  hasher& update(const std::vector<unsigned char>& data);

  /**
   * @brief 分块更新数据（string 版本）
   * @param data 数据字符串
   * @return 当前 hasher 引用，支持链式调用
   * @throw hash_exception 如果对象已 finalized
   * @note 内部将字符串内容按字节处理
   */
  hasher& update(const std::string& data);

  /**
   * @brief 获取最终的二进制摘要
   * @return 二进制 vector
   * @note 调用后对象标记为 finalized，不能再 update 或再次调用 final
   */
  std::vector<unsigned char> final_bin();

  /**
   * @brief 获取最终摘要的十六进制字符串
   * @return hex 字符串
   * @note 调用后对象标记为 finalized，不能再 update 或再次调用 final
   */
  std::string final_hex();
  // 禁用拷贝
  ~hasher() = default;
  hasher(const hasher&) = delete;
  hasher& operator=(const hasher&) = delete;

  // 支持移动
  hasher(hasher&&) noexcept = default;
  hasher& operator=(hasher&&) noexcept = default;

 private:
  hash::alg alg_;   ///< hash 算法类型
  bool finalized_;  ///< 是否已经完成计算

  // ----------------------------
  // OpenSSL 上下文管理
  // 使用 void 指针 + 删除器管理不同类型的上下文
  // ----------------------------
  std::unique_ptr<void, void (*)(void*)> ctx_{nullptr, nullptr};

  // update / final 函数指针（统一接口调用）
  using update_fn = int (*)(void*, const void*, size_t);
  using final_fn = int (*)(void*, unsigned char*);

  update_fn update_func_{nullptr};  ///< 对应算法的 update 函数
  final_fn final_func_{nullptr};    ///< 对应算法的 final 函数

  /**
   * @brief 获取摘要长度（字节数）
   */
  std::size_t digest_length() const;
};

/**
 * @brief 一次性计算字符串的二进制摘要
 * @param data 输入字符串
 * @param hash_alg hash 算法类型
 * @return 摘要 vector
 */
std::vector<unsigned char> compute_bin(const std::string& data, hash::alg hash_alg);

/**
 * @brief 一次性计算字符串的 hex 摘要
 * @param data 输入字符串
 * @param hash_alg hash 算法类型
 * @return 十六进制字符串
 */
std::string compute(const std::string& data, hash::alg hash_alg);

/**
 * @brief 一次性计算文件的二进制摘要
 * @param filepath 文件路径
 * @param hash_alg hash 算法类型
 * @return 摘要 vector
 */
std::vector<unsigned char> compute_file_bin(const std::string& filepath, hash::alg hash_alg);

/**
 * @brief 一次性计算文件的 hex 摘要
 * @param filepath 文件路径
 * @param hash_alg hash 算法类型
 * @return 十六进制字符串
 */
std::string compute_file(const std::string& filepath, hash::alg hash_alg);

}  // namespace hash
}  // namespace cryptx

#endif  // __GUARD_HASH_H_INCLUDE_GUARD__