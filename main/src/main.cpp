#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "cryptx/rsa.h"

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
    std::vector<unsigned char> ciphertext = pub2.encrypt(plaintext, cryptx::rsa::oaep_hash::SHA256);

    // 私钥解密
    std::vector<unsigned char> decrypted = priv2.decrypt(ciphertext, cryptx::rsa::oaep_hash::SHA256);

    std::string recovered(decrypted.begin(), decrypted.end());
    assert(recovered == msg);
    std::cout << "Encrypt/Decrypt test passed: " << recovered << std::endl;

    // 4. 测试签名/验签
    std::vector<unsigned char> signature = priv2.sign(plaintext, cryptx::rsa::hash::SHA256);

    bool ok = pub2.verify(plaintext, signature, cryptx::rsa::hash::SHA256);
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

  return 0;
}
