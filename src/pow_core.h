/** \brief Find the hex string with the indicated difficulty.

This set of functions finds a hex string that has the indicated number of leading zeros
using the supplied authdata string.  The authdata is concatenated with a
suffix, and they are then passsed through a SHA1 hash.  The hash is tested to
see if it has a number of leading zeroes equal to the required difficulty.
This code automatically adjusts the suffix string length so that the solution
space will contain enough possible valid suffixes.

The resulting suffix and calculation time is returned as a 2-element vector of strings:
{suffix, elapsed_time}

The run_pow function should be called to initiate calculations:
run_pow(const char *authdata, int difficulty)
*/
#include <atomic>

constexpr size_t MAX_INPUT_SIZE = 256;
const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Determine suffix length so that keyspace ≥ 2^(difficulty * 4)
size_t determine_suffix_length(int difficulty);

void generate_counter_string(uint64_t counter, char *output, size_t length);

bool has_leading_zeros(const uint8_t *digest, int bits_required);

void pow_worker(const char *authdata, size_t auth_len, int difficulty,
                std::atomic<bool> &found, char *result,
                int thread_id, int total_threads, uint64_t base_counter, size_t suffix_length);

std::vector<std::string> run_pow(const char *authdata, int difficulty);