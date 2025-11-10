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
