#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "cryptx/hash.h"
#include "cryptx/rsa.h"

void test_hash()
{
  using namespace cryptx::hash;

  std::string data = "Hello, CryptX Hash!";

  std::vector<alg> algs = {alg::MD5, alg::SHA1, alg::SHA224, alg::SHA256, alg::SHA384, alg::SHA512};

  std::cout << "=== String Hash Test ===\n";
  for (auto a : algs)
  {
    // 一次性计算
    std::string hex = compute(data, a);
    std::cout << "Algorithm " << static_cast<int>(a) << ": " << hex << "\n";

    // 分块更新
    hasher h(a);
    h.update(data.data(), 5)                        // 前5个字符
      .update(data.data() + 5, 7)                   // 中间7个字符
      .update(data.data() + 12, data.size() - 12);  // 剩余
    std::cout << "Algorithm " << static_cast<int>(a) << " (chunked): " << h.final_hex() << "\n\n";
  }
}

void test_rsa_password_protection()
{
  try
  {
    std::string pwd = "MyStrongPassword123!";

    // 1. 生成私钥（带密码）
    cryptx::rsa::private_key priv(cryptx::rsa::bits::RSA_2048, pwd);

    // 2. 导出加密 PEM
    std::string pem_encrypted = priv.pem(cryptx::rsa::pem_format::PKCS8);
    std::cout << "Encrypted PEM:\n" << pem_encrypted.substr(0, 200) << "...\n";

    // 3. 用正确密码重新加载
    cryptx::rsa::private_key priv2(pem_encrypted, pwd);

    // 4. 获取公钥测试
    cryptx::rsa::public_key pub = priv2.get_public();

    std::string pub_pem = pub.pem();
    std::cout << "Public key PEM:\n" << pub_pem.substr(0, 200) << "...\n";

    // 5. 测试加密/解密
    std::string msg = "Hello, RSA OAEP SHA256 with password!";
    std::vector<unsigned char> plaintext(msg.begin(), msg.end());

    // 公钥加密
    std::vector<unsigned char> ciphertext = pub.encrypt(plaintext);

    // 私钥解密
    std::vector<unsigned char> decrypted = priv2.decrypt(ciphertext);

    std::string recovered(decrypted.begin(), decrypted.end());
    assert(recovered == msg);
    std::cout << "Encrypt/Decrypt test passed: " << recovered << std::endl;

    // 6. 测试签名/验签
    std::vector<unsigned char> signature = priv2.sign(plaintext);
    bool ok = pub.verify(plaintext, signature);
    assert(ok);
    std::cout << "Sign/Verify test passed\n";
  }
  catch (const cryptx::rsa::rsa_exception& e)
  {
    std::cerr << "RSA error: " << e.what() << std::endl;
  }
}

int main()
{
  try
  {
    // 1. 生成私钥
    cryptx::rsa::private_key priv(cryptx::rsa::bits::RSA_2048);
    cryptx::rsa::public_key pub = priv.get_public();

    // 2. 导出 PEM 并重新加载
    std::string priv_pem = priv.pem();  // PKCS8 明文
    std::string pub_pem = pub.pem();

    cryptx::rsa::private_key priv2(priv_pem);
    cryptx::rsa::public_key pub2(pub_pem);

    // 3. 测试加密/解密
    std::string msg = "Hello, RSA OAEP SHA256!";
    std::vector<unsigned char> plaintext(msg.begin(), msg.end());

    // 公钥加密
    std::vector<unsigned char> ciphertext = pub2.encrypt(plaintext);

    // 私钥解密
    std::vector<unsigned char> decrypted = priv2.decrypt(ciphertext);

    std::string recovered(decrypted.begin(), decrypted.end());
    assert(recovered == msg);
    std::cout << "Encrypt/Decrypt test passed: " << recovered << std::endl;

    // 4. 测试签名/验签
    std::vector<unsigned char> signature = priv2.sign(plaintext);

    bool ok = pub2.verify(plaintext, signature);
    assert(ok);
    std::cout << "Sign/Verify test passed" << std::endl;

    // 5. OAEP-SHA1 兼容性测试
    std::vector<unsigned char> c1 = pub2.encrypt(plaintext, cryptx::rsa::oaep_hash::SHA1);
    std::vector<unsigned char> d1 = priv2.decrypt(c1, cryptx::rsa::oaep_hash::SHA1);
    assert(std::string(d1.begin(), d1.end()) == msg);
    std::cout << "Encrypt/Decrypt SHA1 compatibility test passed" << std::endl;
  }
  catch (const cryptx::rsa::rsa_exception& e)
  {
    std::cerr << "RSA error: " << e.what() << std::endl;
    return 1;
  }

  test_rsa_password_protection();
  test_hash();

  return 0;
}
