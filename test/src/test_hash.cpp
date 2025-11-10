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
