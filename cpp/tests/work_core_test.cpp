// work_core_test.cpp
#include "../work_core.h"
#include <gtest/gtest.h>
#include <openssl/sha.h>
#include "../work_core_internal.h"
#include <cmath>
using ::testing::Combine;
using ::testing::Values;
#include <vector>
#include <set>
#include <span>
#include <cstring>

TEST(DetermineSuffixLength, NormalNBits_ValidSuffixLength)
{
    EXPECT_EQ(3, work_internal::determine_suffix_length(16));
}

TEST(DetermineSuffixLength, ZeroNBits)
{
    EXPECT_EQ(0, work_internal::determine_suffix_length(0));
}

TEST(DetermineSuffixLength, MonotonicIncreasingLength)
{
    std::vector<uint8_t> n_bitses = {4, 8, 12, 16, 20, 24};
    uint8_t previous_n_bits = 0;
    for (uint8_t n_bits : n_bitses)
    {
        EXPECT_GE(work_internal::determine_suffix_length(n_bits), work_internal::determine_suffix_length(previous_n_bits));
        previous_n_bits = n_bits;
    }
}

TEST(DetermineSuffixLength, SolutionSpaceSatisfiesInequality)
{
    const uint8_t n_bits = 16;
    const size_t L = work_internal::determine_suffix_length(n_bits);

    // Check L * log2(|Σ|) >= n_bits   (no overflow, stable)
    const long double lhs = static_cast<long double>(L) * std::log2(static_cast<long double>(work_internal::charset_size));
    EXPECT_GE(lhs + 1e-12L, n_bits); // tiny epsilon for FP
}

TEST(GenerateCounterString, ZeroLength_NoWrite)
{
    unsigned char dummy = 0xAB;
    work_internal::generate_counter_string(0, &dummy, 0); // must not touch memory
    EXPECT_EQ(dummy, 0xAB);
}

TEST(GenerateCounterString, ZeroCounter)
{
    unsigned char output[5];
    work_internal::generate_counter_string(0, output, 4);
    unsigned char expected_output[5] = "AAAA";
    EXPECT_EQ(0, memcmp(expected_output, output, 4)) << "bytes differ";
}

struct Case
{
    int counter;
    size_t length;
    const unsigned char *expected_output;
};

class GenerateTest : public ::testing::TestWithParam<Case>
{
};

INSTANTIATE_TEST_SUITE_P(
    Table,
    GenerateTest,
    Values(
        Case{0, 4, (const unsigned char *)"AAAA"},
        Case{1, 4, (const unsigned char *)"AAAB"},
        Case{64, 4, (const unsigned char *)"AABA"}));

TEST_P(GenerateTest, ExpectedOutputs)
{
    auto [counter, length, expected_output] = GetParam();

    unsigned char output[length];
    work_internal::generate_counter_string(counter, output, length);
    std::vector<unsigned char> actual(output, output + length);

    EXPECT_EQ(actual, std::vector<unsigned char>(expected_output, expected_output + length));
}

TEST(GenerateCounterString, AllCharactersBelongToSet)
{
    std::set<char> possibleChars(work_internal::charset, work_internal::charset + work_internal::charset_size);
    ASSERT_NE(possibleChars.find('A'), possibleChars.end());
    unsigned char output[4];

    for (int counter = 0; counter < 100; ++counter)
    {
        work_internal::generate_counter_string(counter, output, 4);
        for (const unsigned char this_char : output)
        {
            EXPECT_NE(possibleChars.find(this_char), possibleChars.end());
        }
    }
}

const unsigned char digest[32]{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00};

TEST(HasTrailingZeros, EnoughTrailingZeros)
{
    EXPECT_TRUE(work_internal::has_trailing_zeros(digest, 24)) << "Not enough trailing zeros";
}

TEST(HasTrailingZeros, NotEnoughTrailingZeros)
{
    EXPECT_FALSE(work_internal::has_trailing_zeros(digest, 28)) << "Too many trailing zeros";
}

TEST(HasTrailingZeros, NotEnoughTrailingZerosByOneBit)
{
    EXPECT_FALSE(work_internal::has_trailing_zeros(digest, 25)) << "Too many trailing zeros";
}

TEST(RunWork, NormalTokenNormalNBits_Success)
{
    const char token[5] = "blah";
    int n_bits = 16;
    WorkResult result = run_work(token, n_bits);
    EXPECT_TRUE(result.found);
}

TEST(RunWork, NoToken_Success)
{
    const char token[1] = {'\0'};
    int n_bits = 16;
    WorkResult result = run_work(token, n_bits);
    EXPECT_TRUE(result.found);
}

TEST(RunWork, NormalTokenZeroNBits_Success)
{
    const char token[5] = "blah";
    int n_bits = 0;
    WorkResult result = run_work(token, n_bits);
    EXPECT_TRUE(result.found);
}

static int trailing_zero_bits(const unsigned char *d, size_t n = SHA256_DIGEST_LENGTH)
{
    int count = 0;
    for (size_t i = 0; i < n; ++i)
    {
        unsigned char byte = d[n - 1 - i];
        if (byte == 0)
        {
            count += 8;
            continue;
        }

        while ((byte & 0x01u) == 0u)
        {
            byte >>= 1;
            ++count;
        }
        return count; // stop at first non-zero byte
    }
    return count; // all zero
}

std::array<unsigned char, 32> sha256(std::span<const unsigned char> data)
{
    std::array<unsigned char, SHA256_DIGEST_LENGTH> output;
    unsigned char *ok = SHA256(data.data(), data.size(), output.data());

    assert(ok == output.data());

    return output;
}

TEST(RunWork, LowNBits_ProducesValidSuffix)
{
    const int len_token = 4;
    const char token[len_token + 1] = "blah";
    int n_bits = 16;
    WorkResult result = run_work(token, n_bits);

    unsigned char input[len_token + result.suffix.size()];
    std::memcpy(input, token, len_token);
    std::memcpy(input + len_token, result.suffix.data(), result.suffix.size());
    std::span<unsigned char> input_span(input, len_token + result.suffix.size());
    std::array<unsigned char, 32> output_hash = sha256(input_span);

    EXPECT_LE(n_bits, trailing_zero_bits(output_hash.data(), SHA256_DIGEST_LENGTH));
}

TEST(RunWork, LongToken_Excepts)
{
    EXPECT_THROW(run_work("ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 4), std::overflow_error);
}