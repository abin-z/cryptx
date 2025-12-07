#define CATCH_CONFIG_MAIN
#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "catch2/catch.hpp"

///////////////////////////////////////////////////////////////////////////////
// 基本算术测试
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("Basic arithmetic", "[math]")
{
  // REQUIRE：断言失败会停止当前 SECTION
  REQUIRE(1 + 1 == 2);

  // CHECK：断言失败不影响后续测试
  CHECK(2 * 3 == 6);

  // 判断为假
  REQUIRE_FALSE(1 + 1 == 3);
}

///////////////////////////////////////////////////////////////////////////////
// 向量操作和 SECTION 嵌套示例
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("Vector operations", "[vector]")
{
  // 每次运行 SECTION 前都会执行这里的初始化
  std::vector<int> v = {1, 2, 3};

  // SECTION 1: 检查初始大小
  SECTION("Check size")
  {
    // v 在这个 SECTION 内仍然是 {1, 2, 3}
    REQUIRE(v.size() == 3);
  }

  // SECTION 2: 查找元素
  SECTION("Find element")
  {
    // v 在这个 SECTION 内还是 {1, 2, 3}，与其他 SECTION 独立
    auto it = std::find(v.begin(), v.end(), 2);
    REQUIRE(it != v.end());
  }

  // SECTION 3: 添加元素
  SECTION("Add element")
  {
    // 每次进入这个 SECTION，v = {1, 2, 3}（独立于其他 SECTION）
    v.push_back(4);  // v = {1, 2, 3, 4}
    REQUIRE(v.size() == 4);

    // 内层 SECTION 3a: 检查新元素
    SECTION("Check new element")
    {
      // 这里 v = {1,2,3,4}，外层 SECTION 的修改有效
      REQUIRE(v[3] == 4);
    }

    // 内层 SECTION 3b: 求和
    SECTION("Sum elements")
    {
      // 这里 v = {1,2,3,4}，与 "Check new element" SECTION 独立
      int sum = 0;
      for (int i : v) sum += i;
      REQUIRE(sum == 10);  // 1+2+3+4
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// 异常测试
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("Exception tests", "[exception]")
{
  auto divide_checked = [](int a, int b) {
    if (b == 0) throw std::runtime_error("divide by zero");
    return a / b;
  };

  // 抛出异常
  REQUIRE_THROWS(divide_checked(1, 0));

  // 不抛异常
  REQUIRE_NOTHROW(divide_checked(4, 2));

  // 指定异常类型
  REQUIRE_THROWS_AS(divide_checked(1, 0), std::runtime_error);
  REQUIRE_THROWS_AS(divide_checked(1, 0), std::exception);

  // 自定义异常消息
  auto throw_msg = []() { throw std::runtime_error("error occurred"); };
  REQUIRE_THROWS_WITH(throw_msg(), "error occurred");
}

///////////////////////////////////////////////////////////////////////////////
// 字符串操作和循环检查
///////////////////////////////////////////////////////////////////////////////
TEST_CASE("String operations and loop", "[string][loop]")
{
  std::string s = "Hello";

  SECTION("Check size and content")
  {
    REQUIRE(s.size() == 5);
    REQUIRE(s.find("ll") != std::string::npos);
  }

  SECTION("Modify string")
  {
    s += "!";
    REQUIRE(s.back() == '!');
  }

  SECTION("Loop check")
  {
    std::vector<int> v = {1, 2, 3, 4, 5};
    for (int i : v)
    {
      CHECK(i > 0);  // CHECK 不会中断循环
    }
  }
}
