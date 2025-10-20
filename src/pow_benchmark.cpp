/* This code finds a hex string that has the indicated number of leading zeros
using the supplied token string.  The token is concatenated with a
suffix, and they are then passsed through a SHA256 hash.  The hash is tested to
see if it has a number of leading zeroes equal to the required difficulty.
This code automatically adjusts the suffix string length so that the solution
space will contain enough possible valid suffixes.

The resulting suffix is output to stdout in the following format:
"RESULT:suffix\n"
"Time: XX seconds\n"

This code should be improved by removing the recasting of variables (in the
pow_worker function).
*/
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <openssl/sha.h>
#include <chrono>
#include <cstring>
#include <random>
#include <cmath>

constexpr size_t MAX_INPUT_SIZE = 256;
const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const size_t charset_size = sizeof(charset) - 1;

// Determine suffix length so that keyspace ≥ 2^(difficulty * 4)
size_t determine_suffix_length(int difficulty) {
    double required_bits = difficulty * 4;
    double bits_per_char = std::log2(charset_size);
    return static_cast<size_t>(std::ceil(required_bits / bits_per_char));
}

void generate_counter_string(uint64_t counter, char* output, size_t length) {
    for (int i = length - 1; i >= 0; --i) {
        output[i] = charset[counter % charset_size];
        counter /= charset_size;
    }
}

bool has_leading_zeros(const uint8_t* digest, int bits_required) {
    int full_bytes = bits_required / 8;
    int remaining_bits = bits_required % 8;

    for (int i = 0; i < full_bytes; ++i) {
        if (digest[i] != 0) return false;
    }

    if (remaining_bits) {
        uint8_t mask = 0xFF << (8 - remaining_bits);
        if ((digest[full_bytes] & mask) != 0) return false;
    }

    return true;
}

void pow_worker(const char* token, size_t auth_len, int difficulty,
                std::atomic<bool>& found, char* result,
                int thread_id, int total_threads, uint64_t base_counter, size_t suffix_length) {

    std::vector<char> suffix(suffix_length + 1, 0);
    alignas(64) char input[MAX_INPUT_SIZE] = {};
    uint8_t digest[SHA_DIGEST_LENGTH];
    int bits_required = difficulty * 4;

    uint64_t counter = base_counter + thread_id;

    while (!found.load()) {
        generate_counter_string(counter, suffix.data(), suffix_length);
        counter += total_threads;

        std::memcpy(input, token, auth_len);
        std::memcpy(input + auth_len, suffix.data(), suffix_length);
        size_t input_len = auth_len + suffix_length;

        SHA256(reinterpret_cast<const uint8_t*>(input), input_len, digest);

        if (has_leading_zeros(digest, bits_required)) {
            std::memcpy(result, suffix.data(), suffix_length);
            result[suffix_length] = '\0';
            found.store(true);
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <token> <difficulty>\n";
        return 1;
    }

    const char* token = argv[1];
    size_t auth_len = std::strlen(token);
    int difficulty = std::stoi(argv[2]);

    size_t suffix_length = determine_suffix_length(difficulty);
    std::cout << "Using suffix length: " << suffix_length << "\n";

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    uint64_t base_counter = dist(gen);

    const int max_threads = std::thread::hardware_concurrency();
    std::atomic<bool> found(false);
    std::vector<char> result(suffix_length + 1, 0);

    std::vector<std::thread> threads;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < max_threads; ++i) {
        threads.emplace_back(pow_worker, token, auth_len, difficulty,
                             std::ref(found), result.data(), i, max_threads, base_counter, suffix_length);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    if (found) {
        std::cout << "RESULT:" << result.data() << "\n";
        std::cout << "Time: " << elapsed.count() << " seconds\n";
    } else {
        std::cerr << "No result found.\n";
    }

    return 0;
}

