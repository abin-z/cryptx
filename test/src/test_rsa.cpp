#include <string>
#include <vector>

#include "catch2/catch.hpp"
#include "cryptx/rsa.h"

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
