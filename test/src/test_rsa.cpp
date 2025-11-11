#include <sstream>
#include <string>
#include <vector>

#include "catch2/catch.hpp"
#include "cryptx/rsa.h"

using namespace cryptx::rsa;

// 将字符串转换为字节数组
static std::vector<unsigned char> to_bytes(const std::string& s)
{
  return std::vector<unsigned char>(s.begin(), s.end());
}

// ----------------------------- 基本测试 -----------------------------
TEST_CASE("RSA key generation and PEM export/import", "[rsa]")
{
  private_key pri(bits::RSA_2048, "mypassword");
  auto pub = pri.get_public();

  SECTION("Export and re-import private key (PKCS8 encrypted)")
  {
    std::string pem_text = pri.pem(pem_format::PKCS8);
    REQUIRE(pem_text.find("BEGIN ENCRYPTED PRIVATE KEY") != std::string::npos);

    private_key pri2(pem_text, "mypassword");
    REQUIRE(pri2.pem().size() > 0);
  }

  SECTION("Export and re-import private key (PKCS1 plaintext)")
  {
    pri.set_password("");  // 明文 PEM
    std::string pem_text = pri.pem(pem_format::PKCS1);
    REQUIRE(pem_text.find("BEGIN RSA PRIVATE KEY") != std::string::npos);

    private_key pri2(pem_text);
    REQUIRE(pri2.public_pem().find("BEGIN PUBLIC KEY") != std::string::npos);
  }

  SECTION("Export and re-import public key")
  {
    std::string pub_pem = pub.pem();
    public_key pub2(pub_pem);
    REQUIRE(pub2.pem() == pub_pem);
  }
}

// ----------------------------- 加解密测试 -----------------------------
TEST_CASE("RSA encrypt/decrypt", "[rsa][encrypt]")
{
  private_key pri(bits::RSA_2048);
  auto pub = pri.get_public();

  std::string msg = "Hello RSA encryption test!";
  auto plaintext = to_bytes(msg);

  SECTION("Encrypt/Decrypt with default OAEP SHA256")
  {
    auto cipher = pub.encrypt(plaintext);
    auto recovered = pri.decrypt(cipher);
    REQUIRE(std::string(recovered.begin(), recovered.end()) == msg);
  }

  SECTION("Encrypt/Decrypt with different OAEP hashes")
  {
    std::vector<oaep_hash> algs = {oaep_hash::SHA1, oaep_hash::SHA256, oaep_hash::SHA384, oaep_hash::SHA512};

    for (auto alg : algs)
    {
      auto cipher = pub.encrypt(plaintext, alg);
      auto recovered = pri.decrypt(cipher, alg);
      REQUIRE(std::string(recovered.begin(), recovered.end()) == msg);
    }
  }

  SECTION("Decrypt with mismatched hash should fail")
  {
    auto cipher = pub.encrypt(plaintext, oaep_hash::SHA256);
    REQUIRE_THROWS_AS(pri.decrypt(cipher, oaep_hash::SHA1), rsa_exception);
  }
}

// ----------------------------- 签名验签测试 -----------------------------
TEST_CASE("RSA sign/verify", "[rsa][sign]")
{
  private_key pri(bits::RSA_2048);
  auto pub = pri.get_public();

  std::string msg = "Test RSA signature";
  auto message = to_bytes(msg);

  SECTION("Sign and verify with SHA256")
  {
    auto sig = pri.sign(message, hash::SHA256);
    REQUIRE(pub.verify(message, sig, hash::SHA256));
  }

  SECTION("Sign and verify with SHA512")
  {
    auto sig = pri.sign(message, hash::SHA512);
    REQUIRE(pub.verify(message, sig, hash::SHA512));
  }

  SECTION("Verify with wrong hash should fail")
  {
    auto sig = pri.sign(message, hash::SHA512);
    REQUIRE_FALSE(pub.verify(message, sig, hash::SHA256));
  }

  SECTION("Verify with modified message should fail")
  {
    auto sig = pri.sign(message);
    auto bad_msg = to_bytes("Modified RSA signature");
    REQUIRE_FALSE(pub.verify(bad_msg, sig));
  }
}

// ----------------------------- I/O 流构造测试 -----------------------------
TEST_CASE("RSA construct from std::istream", "[rsa][io]")
{
  private_key pri(bits::RSA_1024, "pwd");
  std::string pem_text = pri.pem();

  std::istringstream pri_stream(pem_text);
  private_key pri2(pri_stream, "pwd");

  std::string pub_pem = pri2.public_pem();
  std::istringstream pub_stream(pub_pem);
  public_key pub2(pub_stream);

  REQUIRE(pub2.pem().find("BEGIN PUBLIC KEY") != std::string::npos);
}

// ----------------------------- 异常测试 -----------------------------
TEST_CASE("RSA exception handling", "[rsa][exception]")
{
  SECTION("Load invalid PEM should throw")
  {
    std::string invalid_pem = "-----BEGIN INVALID KEY-----\nABC123\n-----END INVALID KEY-----\n";
    REQUIRE_THROWS_AS(private_key(invalid_pem), rsa_exception);
    REQUIRE_THROWS_AS(public_key(invalid_pem), rsa_exception);
  }

  SECTION("Decrypt invalid data should throw")
  {
    private_key pri(bits::RSA_1024);
    std::vector<unsigned char> bad_cipher(16, 0x00);
    REQUIRE_THROWS_AS(pri.decrypt(bad_cipher), rsa_exception);
  }

  SECTION("Verify with random data should return false")
  {
    private_key pri(bits::RSA_1024);
    auto pub = pri.get_public();

    std::vector<unsigned char> msg = to_bytes("12345");
    std::vector<unsigned char> sig(64, 0xAA);
    REQUIRE_FALSE(pub.verify(msg, sig));
  }
}

TEST_CASE("RSA encrypt/decrypt works", "[rsa][encrypt]")
{
  using namespace cryptx::rsa;

  private_key priv(bits::RSA_2048);
  public_key pub = priv.get_public();

  std::string msg = "Hello, RSA OAEP SHA256!";
  std::vector<unsigned char> input(msg.begin(), msg.end());

  auto cipher = pub.encrypt(input);
  auto plain = priv.decrypt(cipher);
  std::string recovered(plain.begin(), plain.end());

  REQUIRE(recovered == msg);
}

TEST_CASE("RSA sign/verify works", "[rsa][sign]")
{
  using namespace cryptx::rsa;

  private_key priv(bits::RSA_2048);
  public_key pub = priv.get_public();

  std::string msg = "Hello, RSA signing!";
  std::vector<unsigned char> data(msg.begin(), msg.end());

  auto sig = priv.sign(data);
  REQUIRE(pub.verify(data, sig));
}

TEST_CASE("RSA password-protected private key works", "[rsa][password]")
{
  using namespace cryptx::rsa;

  std::string password = "MyStrongPassword123!";
  private_key priv(bits::RSA_2048, password);

  std::string pem_enc = priv.pem(pem_format::PKCS8);
  private_key priv2(pem_enc, password);
  public_key pub = priv2.get_public();

  std::string msg = "Hello, RSA with password!";
  std::vector<unsigned char> input(msg.begin(), msg.end());

  auto cipher = pub.encrypt(input);
  auto plain = priv2.decrypt(cipher);

  std::string recovered(plain.begin(), plain.end());
  REQUIRE(recovered == msg);
}

// ----------------------------- 边界与一致性测试 -----------------------------
TEST_CASE("RSA long message split encryption/decryption", "[rsa][large]")
{
  private_key pri(bits::RSA_4096);
  auto pub = pri.get_public();

  // RSA 最大明文长度 < key_bytes - 2*hLen - 2 (OAEP)
  // 对于 4096-bit + SHA256，大约 446 bytes
  const size_t chunk_size = 400;
  std::string base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string msg;
  for (int i = 0; i < 100; ++i) msg += base;  // 约 6200 字节

  // 手动分块加解密
  std::vector<unsigned char> all_encrypted;
  for (size_t i = 0; i < msg.size(); i += chunk_size)
  {
    std::vector<unsigned char> chunk(msg.begin() + i, msg.begin() + std::min(msg.size(), i + chunk_size));
    auto enc = pub.encrypt(chunk);
    all_encrypted.insert(all_encrypted.end(), enc.begin(), enc.end());
  }

  // 逐块解密验证
  std::vector<unsigned char> all_decrypted;
  size_t offset = 0;
  const size_t cipher_chunk = pub.encrypt(std::vector<unsigned char>(1, 'A')).size();
  while (offset < all_encrypted.size())
  {
    std::vector<unsigned char> block(all_encrypted.begin() + offset,
                                     all_encrypted.begin() + std::min(all_encrypted.size(), offset + cipher_chunk));
    auto dec = pri.decrypt(block);
    all_decrypted.insert(all_decrypted.end(), dec.begin(), dec.end());
    offset += cipher_chunk;
  }

  REQUIRE(all_decrypted == std::vector<unsigned char>(msg.begin(), msg.end()));
}

TEST_CASE("RSA consistency between PKCS1 and PKCS8 exports", "[rsa][pem]")
{
  private_key pri(bits::RSA_2048);
  pri.set_password("pass");
  std::string pkcs1 = pri.pem(pem_format::PKCS1);
  std::string pkcs8 = pri.pem(pem_format::PKCS8);

  // 两种格式都应能重新导入并生成相同公钥
  private_key pri1(pkcs1, "pass");
  private_key pri2(pkcs8, "pass");

  REQUIRE(pri1.public_pem() == pri2.public_pem());
}

TEST_CASE("RSA re-imported key performs identical encryption", "[rsa][consistency]")
{
  private_key pri(bits::RSA_2048);
  auto pub = pri.get_public();

  std::string pem = pri.pem();
  private_key pri2(pem);
  auto pub2 = pri2.get_public();

  std::string msg = "re-import test";
  auto bytes = to_bytes(msg);

  auto c1 = pub.encrypt(bytes);
  auto c2 = pub2.encrypt(bytes);

  // 两个公钥加密结果不同（随机性），但解密结果相同
  auto d1 = pri.decrypt(c1);
  auto d2 = pri2.decrypt(c2);
  REQUIRE(d1 == d2);
}

TEST_CASE("RSA public/private pair mismatch should fail", "[rsa][fail]")
{
  private_key pri1(bits::RSA_2048);
  private_key pri2(bits::RSA_2048);

  auto pub1 = pri1.get_public();
  auto pub2 = pri2.get_public();

  std::string msg = "key mismatch test";
  auto bytes = to_bytes(msg);

  auto cipher = pub1.encrypt(bytes);
  REQUIRE_THROWS_AS(pri2.decrypt(cipher), rsa_exception);

  auto sig = pri1.sign(bytes);
  REQUIRE_FALSE(pub2.verify(bytes, sig));
}

TEST_CASE("RSA repeated sign/verify should be stable", "[rsa][repeat]")
{
  private_key pri(bits::RSA_2048);
  auto pub = pri.get_public();
  auto msg = to_bytes("repeat test");

  auto sig1 = pri.sign(msg);
  auto sig2 = pri.sign(msg);

  // PSS 带随机盐 => 每次签名不同
  REQUIRE(sig1 != sig2);
  // 但都能被正确验证
  REQUIRE(pub.verify(msg, sig1));
  REQUIRE(pub.verify(msg, sig2));
}

TEST_CASE("RSA decrypting tampered ciphertext should throw", "[rsa][tamper]")
{
  private_key pri(bits::RSA_2048);
  auto pub = pri.get_public();

  std::string msg = "RSA tamper test";
  auto cipher = pub.encrypt(to_bytes(msg));

  // 修改密文任意一字节
  cipher[cipher.size() / 2] ^= 0x55;

  REQUIRE_THROWS_AS(pri.decrypt(cipher), rsa_exception);
}

TEST_CASE("RSA minimal key (1024-bit) works correctly", "[rsa][small]")
{
  private_key pri(bits::RSA_1024);
  auto pub = pri.get_public();

  auto msg = to_bytes("tiny key test");
  auto enc = pub.encrypt(msg);
  auto dec = pri.decrypt(enc);
  REQUIRE(dec == msg);

  auto sig = pri.sign(msg);
  REQUIRE(pub.verify(msg, sig));
}

TEST_CASE("RSA large key (4096-bit) basic operations", "[rsa][largekey]")
{
  private_key pri(bits::RSA_4096);
  auto pub = pri.get_public();

  auto msg = to_bytes("big key test");
  auto enc = pub.encrypt(msg);
  auto dec = pri.decrypt(enc);
  REQUIRE(dec == msg);
}
