#include <fstream>
#include <string>
#include <vector>

#include "catch2/catch.hpp"
#include "cryptx/hash.h"

TEST_CASE("Hash algorithms produce consistent results", "[hash]")
{
  using namespace cryptx::hash;

  std::string data = "Hello, CryptX Hash!";
  std::vector<alg> algs = {alg::MD5, alg::SHA1, alg::SHA224, alg::SHA256, alg::SHA384, alg::SHA512};

  for (auto a : algs)
  {
    // 一次性计算
    std::string hex1 = compute(data, a);

    // 分块计算
    hasher h(a);
    h.update(data.data(), 5).update(data.data() + 5, 7).update(data.data() + 12, data.size() - 12);
    std::string hex2 = h.final_hex();

    REQUIRE(hex1 == hex2);
  }
}

TEST_CASE("Hasher handles empty input correctly", "[hash][edge]")
{
  using namespace cryptx::hash;

  for (auto a : {alg::MD5, alg::SHA256})
  {
    std::string result = compute("", a);
    REQUIRE(!result.empty());
  }
}

using namespace cryptx::hash;

TEST_CASE("Hash: one-shot string hash matches incremental hash", "[hash]")
{
  std::string data = "The quick brown fox jumps over the lazy dog";

  std::vector<alg> algs = {alg::MD5, alg::SHA1, alg::SHA224, alg::SHA256, alg::SHA384, alg::SHA512};

  for (auto a : algs)
  {
    SECTION("Algorithm " + std::to_string(static_cast<int>(a)))
    {
      // 一次性计算
      std::string hex1 = compute(data, a);

      // 分块计算
      hasher h(a);
      h.update(data.data(), 10).update(data.data() + 10, 15).update(data.data() + 25, data.size() - 25);
      std::string hex2 = h.final_hex();

      REQUIRE(hex1 == hex2);
    }
  }
}

TEST_CASE("Hash: compute_bin returns correct size", "[hash]")
{
  std::string data = "Hello, world!";
  hasher h1(alg::MD5);
  std::vector<unsigned char> bin1 = compute_bin(data, alg::MD5);
  REQUIRE(bin1.size() == 16);  // MD5 16 bytes

  std::vector<unsigned char> bin2 = compute_bin(data, alg::SHA256);
  REQUIRE(bin2.size() == 32);  // SHA256 32 bytes
}

TEST_CASE("Hash: hasher final_bin and final_hex consistency", "[hash]")
{
  std::string data = "Test data for hash";
  cryptx::hash::hasher h(cryptx::hash::alg::SHA1);

  // 更新数据
  h.update(data.data(), data.size());

  // 只调用一次 final_bin
  auto bin = h.final_bin();
  REQUIRE(bin.size() == 20);  // SHA1 输出 20 字节

  // 手动把二进制转成 hex
  std::string hex_from_bin;
  static const char* hex_chars = "0123456789abcdef";
  for (auto b : bin)
  {
    hex_from_bin.push_back(hex_chars[(b >> 4) & 0xF]);
    hex_from_bin.push_back(hex_chars[b & 0xF]);
  }

  // final_hex() 本质上就是同样的转换
  std::string hex = cryptx::hash::compute(data, cryptx::hash::alg::SHA1);
  REQUIRE(hex_from_bin == hex);
  REQUIRE(hex.size() == 40);  // 20字节转 hex
}

TEST_CASE("Hash: repeated final throws exception", "[hash]")
{
  hasher h(alg::SHA256);
  h.update("abc");
  h.final_hex();
  REQUIRE_THROWS_AS(h.update("def"), hash_exception);
  REQUIRE_THROWS_AS(h.final_bin(), hash_exception);
}

TEST_CASE("Hash: file hash matches manual content hash", "[hash][file]")
{
  // 临时文件
  std::string tmpfile = "tmp_test_hash.txt";
  std::ofstream ofs(tmpfile);
  ofs << "Hello, file hashing!";
  ofs.close();

  std::string hex_file = compute_file(tmpfile, alg::SHA256);

  // 手动读取文件内容
  std::ifstream ifs(tmpfile, std::ios::binary);
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
  std::string hex_manual = compute(std::string(data.begin(), data.end()), alg::SHA256);

  REQUIRE(hex_file == hex_manual);

  // 清理
  std::remove(tmpfile.c_str());
}

TEST_CASE("Hash: compute_file_bin returns correct length", "[hash][file]")
{
  std::string tmpfile = "tmp_test_hash_bin.txt";
  std::ofstream ofs(tmpfile);
  ofs << "1234567890";
  ofs.close();

  auto bin = compute_file_bin(tmpfile, alg::MD5);
  REQUIRE(bin.size() == 16);

  bin = compute_file_bin(tmpfile, alg::SHA512);
  REQUIRE(bin.size() == 64);

  std::remove(tmpfile.c_str());
}