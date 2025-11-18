// pow_core_test.cpp
#include "../pow_core.h"
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include "../pow_core_internal.h"
#include <cmath>
using ::testing::Combine;
using ::testing::Values;
#include <vector>
#include <set>
#include <span>
#include <cstring>

// size_t determine_suffix_length(uint8_t difficulty);
TEST(DetermineSuffixLength, NormalDifficulty_ValidSuffixLength)
{
    EXPECT_EQ(3, pow_internal::determine_suffix_length(4));
}

TEST(DetermineSuffixLength, ZeroDifficulty)
{
    EXPECT_EQ(0, pow_internal::determine_suffix_length(0));
}

TEST(DetermineSuffixLength, MonotonicIncreasingLength)
{
    std::vector<uint8_t> difficulties = {1, 2, 3, 4, 5, 6};
    uint8_t previous_difficulty = 0;
    for (uint8_t difficulty : difficulties)
    {
        EXPECT_GE(pow_internal::determine_suffix_length(difficulty), pow_internal::determine_suffix_length(previous_difficulty));
        previous_difficulty = difficulty;
    }
}

TEST(DetermineSuffixLength, SolutionSpace)
{
    size_t length = 3;
    uint8_t difficulty = 4;
    EXPECT_GE(std::pow(pow_internal::charset_size, length), std::pow(2, 4 * difficulty));
}

TEST(GenerateCounterString, ZeroCounter)
{
    unsigned char output[5];
    pow_internal::generate_counter_string(0, output, 4);
    unsigned char expected_output[5] = "AAAA";
    EXPECT_EQ(0, memcmp(expected_output, output, 4)) << "bytes differ";
}

struct Case
{
    int counter;
    size_t length;
    unsigned char *expected_output;
};

class GenerateTest : public ::testing::TestWithParam<Case>
{
};

TEST_P(GenerateTest, ExpectedOutputs)
{
    auto [counter, length, expected_output] = GetParam();
    std::vector<unsigned char> char_vector(expected_output, expected_output + length);

    unsigned char output[length];
    pow_internal::generate_counter_string(counter, output, length);

    EXPECT_EQ(char_vector, std::vector<unsigned char>(expected_output, expected_output + length));
}

unsigned char expected_output1[5] = "AAAA";
unsigned char expected_output2[5] = "BAAA";
unsigned char expected_output3[5] = "ABAA";

INSTANTIATE_TEST_SUITE_P(
    Table,
    GenerateTest,
    Values(
        Case{0, 4, expected_output1},
        Case{1, 4, expected_output2},
        Case{64, 4, expected_output3}));

TEST(GenerateCounterString, AllCharactersBelongToSet)
{
    std::set<char> possibleChars(pow_internal::charset, pow_internal::charset + 64);
    ASSERT_NE(possibleChars.find('A'), possibleChars.end());
    unsigned char output[4];

    for (int counter = 0; counter < 100; ++counter)
    {
        pow_internal::generate_counter_string(counter, output, 4);
        for (const char this_char : output)
        {
            //            std::cout << "Considering " << this_char << "\n";
            EXPECT_NE(possibleChars.find(this_char), possibleChars.end());
        }
    }
}

const unsigned char digest[20]{0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80};

TEST(HasLeadingZeros, EnoughLeadingZeros)
{
    EXPECT_TRUE(pow_internal::has_leading_zeros(digest, 24)) << "Not enough leading zeros";
}

TEST(HasLeadingZeros, NotEnoughLeadingZeros)
{
    EXPECT_FALSE(pow_internal::has_leading_zeros(digest, 28)) << "Not enough leading zeros";
}

TEST(HasLeadingZeros, NotEnoughLeadingZerosByOneBit)
{
    EXPECT_FALSE(pow_internal::has_leading_zeros(digest, 25)) << "Not enough leading zeros";
}

TEST(RunPow, NormalAuthNormalDifficulty_Success)
{
    const char authdata[5] = "blah";
    int difficulty = 4;
    PowResult result = run_pow(authdata, difficulty);
    EXPECT_TRUE(result.found);
}

TEST(RunPow, NoAuth_Success)
{
    const char authdata[1] = {'\0'};
    int difficulty = 4;
    PowResult result = run_pow(authdata, difficulty);
    EXPECT_TRUE(result.found);
    //    std::cout << result.suffix << "\n";
}

TEST(RunPow, NormalAuthZeroDifficulty_Success)
{
    const char authdata[5] = "blah";
    int difficulty = 0;
    PowResult result = run_pow(authdata, difficulty);
    EXPECT_TRUE(result.found);
}

static int leading_zero_bits(const unsigned char *d, size_t n = SHA_DIGEST_LENGTH)
{
    int count = 0;
    for (size_t i = 0; i < n; ++i)
    {
        if (d[i] == 0)
        {
            count += 8;
            continue;
        }
        unsigned char b = d[i];
        while ((b & 0x80u) == 0u)
        {
            b <<= 1;
            ++count;
        }
        return count; // stop at first non-zero byte
    }
    return count; // all zero
}

std::array<unsigned char, 20> sha1(std::span<unsigned char> data)
{
    std::array<unsigned char, SHA_DIGEST_LENGTH> output;
    unsigned char *ok = SHA1(data.data(), data.size(), output.data());

    assert(ok == output.data());
    /*
    std::ostringstream oss;
    for (unsigned char i : output)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(i);
        //        std::cout << std::hex << i;
    }
    std::cout << oss.str() << "\n";
    */
    return output;
}

TEST(RunPow, LowDifficulty_ProducesValidSuffix)
{
    const char authdata[5] = "blah";
    int difficulty = 4;
    PowResult result = run_pow(authdata, difficulty);

    unsigned char input[4 + result.suffix.size()];
    std::memcpy(input, authdata, 4);
    std::memcpy(input + 4, result.suffix.data(), result.suffix.size());
    std::span<unsigned char> input_span(input, 4 + result.suffix.size());
    std::array<unsigned char, 20> output_hash = sha1(input_span);

    /*
    std::ostringstream oss;
    for (unsigned char i : output_hash)
    {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(i);
        //        std::cout << std::hex << i;
    }
    std::cout << oss.str() << "\n";
    */

    EXPECT_EQ(16, leading_zero_bits(output_hash.data(), SHA_DIGEST_LENGTH));
}

TEST(RunPow, LongAuthdata_Excepts)
{
    EXPECT_THROW(run_pow("ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 4), std::overflow_error);
}
// PowResult run_pow(const char *authdata, int difficulty);
// Threads availability: handle hardware_concurrency()==0 fallback.

/*
TEST(MinValueTest, HandlesNormalVector) { ASSERT_EQ(min_value({1, 2, 3, 4}), 1); }

class StatsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Called before *each* test using this fixture
        pressures = {0.0, 100.0, 50.0, 75.0, 89.0};
        tiny = {1.0};
        empty = {};
    }

    // Optional: TearDown() override { ... }

    std::vector<double> pressures;
    std::vector<double> tiny;
    std::vector<double> empty;
    double tol = 1e-9;
};

// Now use TEST_F instead of TEST

TEST_F(StatsTest, MinValueWorksOnNormalVector) { EXPECT_DOUBLE_EQ(min_value(pressures), 0.0); }

TEST_F(StatsTest, MinThrowsOnEmptyVector) { EXPECT_THROW(min_value(empty), std::invalid_argument); }

*/
