// pow_core.cpp
#include <iostream>
#include <thread>
#include <vector>
#include <openssl/sha.h>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>
#include "pow_core.h"
#include "pow_core_internal.h"
#include <cassert>

namespace
{

    void pow_worker(const char *token, size_t auth_len, uint8_t difficulty,
                    std::atomic<bool> &found, char *result,
                    int thread_id, int total_threads, uint64_t base_counter, size_t suffix_length)
    {
        unsigned char digest[SHA_DIGEST_LENGTH]{};
        unsigned char suffix[suffix_length + 1]{};
        alignas(64) unsigned char input[pow_internal::MAX_INPUT_SIZE] = {};

        int bits_required = difficulty * 4;

        uint64_t counter = base_counter + thread_id;

        while (!found.load())
        {
            pow_internal::generate_counter_string(counter, suffix, suffix_length);
            counter += total_threads;

            size_t input_len = auth_len + suffix_length;
            if (input_len > pow_internal::MAX_INPUT_SIZE)
            {
                throw std::runtime_error("Authdata is too long.");
            }
            std::memcpy(input, token, auth_len);
            std::memcpy(input + auth_len, suffix, suffix_length);

            SHA256(input, input_len, digest);

            if (pow_internal::has_leading_zeros(digest, bits_required))
            {
                std::memcpy(result, suffix, suffix_length);
                result[suffix_length] = '\0';
                found.store(true);
                break;
            }
        }
    }

}

namespace pow_internal
{
    // Determine suffix length so that keyspace ≥ 2^(difficulty * 4)
    size_t determine_suffix_length(uint8_t difficulty)
    {
        double required_bits = difficulty * 4;
        double bits_per_char = std::log2(pow_internal::charset_size);
        return static_cast<size_t>(std::ceil(required_bits / bits_per_char));
    }

    void generate_counter_string(uint64_t counter, unsigned char *output, size_t output_length)
    {
        assert(output != nullptr);
        if (output_length == 0)
            return;
        for (int i = output_length - 1; i >= 0; --i)
        {
            output[i] = pow_internal::charset[counter % pow_internal::charset_size];
            counter /= pow_internal::charset_size;
        }
    }

    bool has_leading_zeros(const unsigned char *digest, int bits_required)
    {
        int full_bytes = bits_required / 8;
        int remaining_bits = bits_required % 8;

        for (int i = 0; i < full_bytes; ++i)
        {
            if (digest[i] != 0)
                return false;
        }

        if (remaining_bits)
        {
            const unsigned char mask = static_cast<unsigned char>(0xFF << (8 - remaining_bits));
            if ((digest[full_bytes] & mask) != 0)
                return false;
        }

        return true;
    }
}

PowResult run_pow(const char *token, uint8_t difficulty)
{
    size_t auth_len = std::strlen(token);

    size_t suffix_length = pow_internal::determine_suffix_length(difficulty);

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    uint64_t base_counter = dist(gen);

    int max_threads = std::thread::hardware_concurrency();
    if (max_threads < 1)
    {
        max_threads = 1;
    }

    std::atomic<bool> found(false);
    std::vector<char> result(suffix_length + 1, 0);

    std::vector<std::thread> threads;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < max_threads; ++i)
    {
        threads.emplace_back(pow_worker, token, auth_len, difficulty,
                             std::ref(found), result.data(), i, max_threads, base_counter, suffix_length);
    }

    for (auto &t : threads)
    {
        if (t.joinable())
            t.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::string elapsed_time = std::to_string(elapsed.count());

    std::string suffix = result.data();

    if (found)
    {

        return PowResult{
            suffix, elapsed_time, found};
    }
    else
    {
        return PowResult{
            "", elapsed_time, found};
    }
}
