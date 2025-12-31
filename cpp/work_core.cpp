// work_core.cpp
#include <iostream>
#include <thread>
#include <vector>
#include <openssl/sha.h>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>
#include "work_core.h"
#include "work_core_internal.h"
#include <cassert>
#include <bitset>

namespace
{

    void work_worker(const char *token, size_t token_len, uint8_t n_bits,
                    std::atomic<bool> &found, char *result,
                    int thread_id, int total_threads, uint64_t base_counter, size_t suffix_length)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH]{};
        std::vector<unsigned char> suffix(suffix_length + 1);

        const int bits_required = n_bits;
        uint64_t counter = base_counter + thread_id;

        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        SHA256_CTX sha_context_base;
        SHA256_Init(&sha_context_base);
        SHA256_Update(&sha_context_base, token, token_len);
        #pragma GCC diagnostic pop

        while (!found.load(std::memory_order_acquire))
        {
            work_internal::generate_counter_string(counter, suffix.data(), suffix_length);
            counter += total_threads;

            const size_t input_len = token_len + suffix_length;
            if (input_len > work_internal::MAX_INPUT_SIZE)
                throw std::runtime_error("Token is too long.");

            #pragma GCC diagnostic push
            #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            SHA256_CTX sha_context = sha_context_base;
            SHA256_Update(&sha_context, suffix.data(), suffix_length);
            SHA256_Final(digest, &sha_context);
            #pragma GCC diagnostic pop

            if (work_internal::has_trailing_zeros(digest, bits_required))
            {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
                {
                    // This thread wins: it's the ONLY writer.
                    std::memcpy(result, suffix.data(), suffix_length);
                    result[suffix_length] = '\0';
                }
                break; // winner or loser, stop after a hit
            }
        }
    }
}

namespace work_internal
{
    // Determine suffix length so that keyspace ≥ 2^n_bits
    size_t determine_suffix_length(uint8_t n_bits)
    {
        double bits_per_char = std::log2(work_internal::charset_size);
        return static_cast<size_t>(std::ceil(n_bits / bits_per_char));
    }

    void generate_counter_string(uint64_t counter, unsigned char *output, size_t output_length)
    {
        assert(output != nullptr);
        if (output_length == 0)
            return;
        for (int i = output_length - 1; i >= 0; --i)
        {
            output[i] = work_internal::charset[counter % work_internal::charset_size];
            counter /= work_internal::charset_size;
        }
    }

    bool has_trailing_zeros(const unsigned char *digest, int bits_required)
    {
        if (bits_required <= 0)
            return true;
        if (digest == nullptr)
            return false;

        constexpr int DIGEST_LEN = SHA256_DIGEST_LENGTH;

        int full_bytes = bits_required / 8;
        int remaining_bits = bits_required % 8;

        // Check full zero bytes at the end of the digest
        for (int i = 0; i < full_bytes; ++i)
        {
            if (digest[DIGEST_LEN - 1 - i] != 0)
                return false;
        }

        // Check remaining bits in the next byte
        if (remaining_bits)
        {
            const unsigned char mask = static_cast<unsigned char>((1u << remaining_bits) - 1u);

            const int idx = DIGEST_LEN - 1 - full_bytes; // next byte before the zero bytes
            if ((digest[idx] & mask) != 0)
                return false;
        }

        return true;
    }
}

WorkResult run_work(const char *token, uint8_t n_bits)
{
    size_t token_len = std::strlen(token);

    size_t suffix_length = work_internal::determine_suffix_length(n_bits);

    if (token_len + suffix_length > work_internal::MAX_INPUT_SIZE)
    {
        throw std::overflow_error("Token length is too long.");
    }

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
        threads.emplace_back(work_worker, token, token_len, n_bits,
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

        return WorkResult{
            suffix, elapsed_time, found};
    }
    else
    {
        return WorkResult{
            "", elapsed_time, found};
    }
}
