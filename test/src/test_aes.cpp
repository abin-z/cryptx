#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "catch2/catch.hpp"
#include "cryptx/aes.h"

static void print_hex(const std::vector<uint8_t>& data)
{
  for (auto b : data) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  std::cout << std::dec << std::endl;
}

static std::vector<uint8_t> to_bytes(const std::string& s)
{
  return std::vector<uint8_t>(s.begin(), s.end());
}

// 辅助函数：比较两段二进制数据是否相同
static bool equal_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
  return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

using namespace cryptx::aes;

TEST_CASE("AES CBC mode basic encrypt/decrypt", "[aes][cbc]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();

  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_256, key, iv);
  auto plaintext = to_bytes("hello abin, AES CBC mode test");

  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES CFB mode works correctly", "[aes][cfb]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CFB, padding_mode::None, key_len::AES_128, key, iv);

  auto plaintext = to_bytes("this is a CFB mode message!");
  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES OFB mode works correctly", "[aes][ofb]")
{
  auto key = cipher::random_key(key_len::AES_192);
  auto iv = cipher::random_iv();
  options opts(mode::OFB, padding_mode::None, key_len::AES_192, key, iv);

  auto plaintext = to_bytes("stream encryption test - OFB");
  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES CTR mode basic roundtrip", "[aes][ctr]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CTR, padding_mode::None, key_len::AES_128, key, iv);

  auto plaintext = to_bytes("stream encryption test - CTR");
  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES update/final streaming API", "[aes][stream]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_256, key, iv);

  const std::string message = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  cipher enc(opts, true);
  cipher dec(opts, false);

  // 模拟分块输入
  std::vector<uint8_t> encrypted;
  encrypted.reserve(message.size() + 32);
  for (size_t i = 0; i < message.size(); i += 10)
  {
    auto part =
      enc.update(reinterpret_cast<const uint8_t*>(message.data() + i), std::min<size_t>(10, message.size() - i));
    encrypted.insert(encrypted.end(), part.begin(), part.end());
  }
  auto fin = enc.final();
  encrypted.insert(encrypted.end(), fin.begin(), fin.end());

  // 解密同样分块处理
  std::vector<uint8_t> decrypted;
  decrypted.reserve(encrypted.size());
  for (size_t i = 0; i < encrypted.size(); i += 8)
  {
    auto part = dec.update(&encrypted[i], std::min<size_t>(8, encrypted.size() - i));
    decrypted.insert(decrypted.end(), part.begin(), part.end());
  }
  auto fin2 = dec.final();
  decrypted.insert(decrypted.end(), fin2.begin(), fin2.end());

  REQUIRE(equal_bytes(to_bytes(message), decrypted));
}

TEST_CASE("AES no padding requires block aligned input", "[aes][padding]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::None, key_len::AES_128, key, iv);

  std::vector<uint8_t> invalid_plain(15, 0x11);  // not 16-byte aligned

  REQUIRE_THROWS_AS(cipher::encrypt(invalid_plain, opts), aes_exception);
}

TEST_CASE("AES random key and IV are random enough", "[aes][random]")
{
  auto k1 = cipher::random_key(key_len::AES_256);
  auto k2 = cipher::random_key(key_len::AES_256);
  auto i1 = cipher::random_iv();
  auto i2 = cipher::random_iv();

  REQUIRE_FALSE(equal_bytes(k1, k2));
  REQUIRE_FALSE(equal_bytes(i1, i2));
}

TEST_CASE("AES deterministic output with same key/iv/plaintext", "[aes][deterministic]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_128, key, iv);

  auto plain = to_bytes("same input same output");
  auto c1 = cipher::encrypt(plain, opts);
  auto c2 = cipher::encrypt(plain, opts);

  REQUIRE(equal_bytes(c1, c2));
}

TEST_CASE("AES throws when key length mismatches mode", "[aes][invalid]")
{
  options opts;
  opts.cipher_mode = mode::CBC;
  opts.pad_mode = padding_mode::PKCS7;
  opts.key_bits = key_len::AES_256;
  opts.key = std::vector<uint8_t>(10, 0xAA);  // invalid length
  opts.iv = cipher::random_iv();

  std::vector<uint8_t> dummy(16, 0x00);
  REQUIRE_THROWS_AS(cipher::encrypt(dummy, opts), aes_exception);
}

TEST_CASE("AES basic encrypt/decrypt consistency", "[aes]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();

  options opts;
  opts.cipher_mode = mode::CBC;
  opts.pad_mode = padding_mode::PKCS7;
  opts.key_bits = key_len::AES_256;
  opts.key = key;
  opts.iv = iv;

  const std::string text = "hello abin, AES test message!";
  std::vector<uint8_t> plaintext(text.begin(), text.end());

  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES random key/iv length validation", "[aes]")
{
  auto key = cipher::random_key(key_len::AES_192);
  auto iv = cipher::random_iv();

  REQUIRE(key.size() == static_cast<size_t>(key_len::AES_192));
  REQUIRE(iv.size() == 16);
}

TEST_CASE("AES CTR mode works correctly", "[aes]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();

  options opts(mode::CTR, padding_mode::None, key_len::AES_128, key, iv);

  std::string msg = "stream mode test - CTR";
  std::vector<uint8_t> plaintext(msg.begin(), msg.end());

  auto ciphertext = cipher::encrypt(plaintext, opts);
  auto decrypted = cipher::decrypt(ciphertext, opts);

  REQUIRE(equal_bytes(plaintext, decrypted));
}

TEST_CASE("AES encryption is deterministic for same input", "[aes]")
{
  // 同样的输入、key、iv、模式 => 输出应一致
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();

  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_128, key, iv);

  std::string msg = "deterministic encryption test";
  std::vector<uint8_t> plaintext(msg.begin(), msg.end());

  auto c1 = cipher::encrypt(plaintext, opts);
  auto c2 = cipher::encrypt(plaintext, opts);

  REQUIRE(equal_bytes(c1, c2));
}

TEST_CASE("AES invalid key/iv throws exception", "[aes]")
{
  options bad_opts;
  bad_opts.cipher_mode = mode::CBC;
  bad_opts.pad_mode = padding_mode::PKCS7;
  bad_opts.key_bits = key_len::AES_256;
  bad_opts.key = {1, 2, 3};  // 错误的 key 长度
  bad_opts.iv = cipher::random_iv();

  std::vector<uint8_t> data = {'x', 'y', 'z'};

  REQUIRE_THROWS_AS(cipher::encrypt(data, bad_opts), aes_exception);
}

TEST_CASE("AES CBC encryption/decryption works correctly", "[aes][cbc]")
{
  using namespace cryptx::aes;

  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();

  options opts;
  opts.cipher_mode = mode::CBC;
  opts.pad_mode = padding_mode::PKCS7;
  opts.key_bits = key_len::AES_256;
  opts.key = key;
  opts.iv = iv;

  std::string text = "hello abin, this is AES CBC test!";
  std::vector<uint8_t> input(text.begin(), text.end());

  auto encrypted = cipher::encrypt(input, opts);
  auto decrypted = cipher::decrypt(encrypted, opts);
  std::string plain(decrypted.begin(), decrypted.end());

  REQUIRE(plain == text);
}

TEST_CASE("AES encrypt/decrypt fails gracefully on wrong key", "[aes][error]")
{
  using namespace cryptx::aes;

  auto key1 = cipher::random_key(key_len::AES_256);
  auto key2 = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();

  options opts1{mode::CBC, padding_mode::PKCS7, key_len::AES_256, key1, iv};
  options opts2{mode::CBC, padding_mode::PKCS7, key_len::AES_256, key2, iv};

  std::string text = "test aes error key";
  std::vector<uint8_t> input(text.begin(), text.end());
  auto encrypted = cipher::encrypt(input, opts1);

  REQUIRE_THROWS(cipher::decrypt(encrypted, opts2));
}

TEST_CASE("AES encrypt/decrypt empty input", "[aes][edge]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_128, key, iv);

  std::vector<uint8_t> empty;
  auto ciphered = cipher::encrypt(empty, opts);
  auto plain = cipher::decrypt(ciphered, opts);

  REQUIRE(equal_bytes(empty, plain));
}

TEST_CASE("AES encrypt/decrypt large input (1MB)", "[aes][edge][performance]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_256, key, iv);

  std::vector<uint8_t> data(1024 * 1024, 0xAB);  // 1 MB
  auto encrypted = cipher::encrypt(data, opts);
  auto decrypted = cipher::decrypt(encrypted, opts);

  REQUIRE(equal_bytes(data, decrypted));
}

// -------------------------------------------------------
// 重复调用测试
// -------------------------------------------------------

TEST_CASE("AES multiple consecutive encrypt/decrypt", "[aes][state]")
{
  auto key = cipher::random_key(key_len::AES_192);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_192, key, iv);

  auto msg = to_bytes("repeated encryptions test");
  auto c1 = cipher::encrypt(msg, opts);
  auto c2 = cipher::encrypt(msg, opts);
  auto d1 = cipher::decrypt(c1, opts);
  auto d2 = cipher::decrypt(c2, opts);

  REQUIRE(equal_bytes(msg, d1));
  REQUIRE(equal_bytes(msg, d2));
}

TEST_CASE("AES calling final() twice throws exception", "[aes][finalize]")
{
  auto key = cipher::random_key(key_len::AES_128);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_128, key, iv);

  cipher enc(opts, true);
  auto data = to_bytes("some data block");
  auto out1 = enc.update(data.data(), data.size());
  auto out2 = enc.final();

  REQUIRE_THROWS_AS(enc.final(), aes_exception);  // 二次 final 必须报错
}

// -------------------------------------------------------
// 不同 key 长度测试
// -------------------------------------------------------

TEST_CASE("AES supports all key lengths (128/192/256)", "[aes][keylen]")
{
  std::vector<key_len> lengths = {key_len::AES_128, key_len::AES_192, key_len::AES_256};

  for (auto len : lengths)
  {
    auto key = cipher::random_key(len);
    auto iv = cipher::random_iv();

    options opts(mode::CBC, padding_mode::PKCS7, len, key, iv);

    auto msg = to_bytes("key length test");
    auto encrypted = cipher::encrypt(msg, opts);
    auto decrypted = cipher::decrypt(encrypted, opts);

    REQUIRE(equal_bytes(msg, decrypted));
  }
}

// -------------------------------------------------------
// 随机性验证（非全零）
// -------------------------------------------------------

TEST_CASE("AES random key/iv are not all zero", "[aes][randomness]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();

  bool all_zero_key = std::all_of(key.begin(), key.end(), [](uint8_t b) { return b == 0; });
  bool all_zero_iv = std::all_of(iv.begin(), iv.end(), [](uint8_t b) { return b == 0; });

  REQUIRE_FALSE(all_zero_key);
  REQUIRE_FALSE(all_zero_iv);
}

// -------------------------------------------------------
// 流式处理: 跨多次 update 验证完整性
// -------------------------------------------------------

TEST_CASE("AES multi-update consistency test", "[aes][stream]")
{
  auto key = cipher::random_key(key_len::AES_256);
  auto iv = cipher::random_iv();
  options opts(mode::CBC, padding_mode::PKCS7, key_len::AES_256, key, iv);

  cipher enc(opts, true);
  cipher dec(opts, false);

  std::string long_msg(4096, 'A');
  std::vector<uint8_t> plain(long_msg.begin(), long_msg.end());
  std::vector<uint8_t> encrypted, decrypted;

  for (size_t i = 0; i < plain.size(); i += 512)
  {
    auto part = enc.update(&plain[i], std::min<size_t>(512, plain.size() - i));
    encrypted.insert(encrypted.end(), part.begin(), part.end());
  }
  auto fin_enc = enc.final();
  encrypted.insert(encrypted.end(), fin_enc.begin(), fin_enc.end());

  for (size_t i = 0; i < encrypted.size(); i += 400)
  {
    auto part = dec.update(&encrypted[i], std::min<size_t>(400, encrypted.size() - i));
    decrypted.insert(decrypted.end(), part.begin(), part.end());
  }
  auto fin_dec = dec.final();
  decrypted.insert(decrypted.end(), fin_dec.begin(), fin_dec.end());

  REQUIRE(equal_bytes(plain, decrypted));
}