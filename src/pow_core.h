/** \file pow_core.h
\brief Find the hex string with the indicated difficulty.

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

/** \brief Maximum concatenated input size (authdata + suffix) fed to SHA-1.

Increase if your authdata can be longer than this.
\see run_pow
 */
constexpr size_t MAX_INPUT_SIZE = 256;

/** \brief Character set to be used for creating suffix.
 */
const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * \brief Compute minimal suffix length so keyspace ≥ 2^(difficulty*4).
 *
 * \param difficulty Number of leading hex zeros (nibbles) required.
 * \return Suffix length in characters.
 *
 * \note Each step of difficulty adds 4 bits.
 */
size_t determine_suffix_length(int difficulty);

/**
 * \brief Encode \p counter into a fixed-length base-\p charset string.
 *
 * Fills \p output[0..length-1] with characters from ::charset.
 *
 * \param counter       Non-negative integer to encode.
 * \param output        Destination buffer of size at least \p length.
 * \param length        Exact number of characters to write (no terminator).
 */
void generate_counter_string(uint64_t counter, unsigned char *output, size_t length);

/**
 * \brief Check whether the first \p bits_required bits of \p digest are zero.
 *
 * \param digest        20-byte SHA-1 digest.
 * \param bits_required Number of leading zero bits required.
 * \return true if the condition holds, false otherwise.
 */
bool has_leading_zeros(const uint8_t *digest, int bits_required);

/**
 * \brief Per-thread worker that searches disjoint counters for a valid suffix.
 *
 * Writes the found suffix into \p result (NUL-terminated) and sets \p found.
 *
 * \param authdata      View of the fixed auth string (read-only).
 * \param difficulty    Required leading zero bits / 4 (hex nibbles).
 * \param found         Shared stop flag; set to true when a solution is found.
 * \param result        Shared output buffer (size ≥ suffix_length+1).
 * \param thread_id     This thread’s id in [0,total_threads).
 * \param total_threads Total worker threads.
 * \param base_counter  Global starting counter (thread_id is added to stride).
 * \param suffix_length Length of suffix to generate.
 *
 * \warning The caller must ensure \p result has sufficient storage and that
 * all threads join before \p result is read.
 */
void pow_worker(const char *authdata, size_t auth_len, int difficulty,
                std::atomic<bool> &found, char *result,
                int thread_id, int total_threads, uint64_t base_counter, size_t suffix_length);

/**
 * \brief Struct to return results.
 *
 * Pair of (suffix, seconds).
 */
struct PowResult
{
    std::string suffix;
    std::string seconds;
    bool found;
};

/**
 * \brief Run the parallel search and return the result and elapsed time.
 *
 * \param authdata   Input string concatenated before the suffix.
 * \param difficulty Required leading hex zeros (nibbles).
 * \return PowResult. If not found within the search window,
 *         suffix is empty and seconds still reflects elapsed time.
 */
PowResult run_pow(const char *authdata, int difficulty);