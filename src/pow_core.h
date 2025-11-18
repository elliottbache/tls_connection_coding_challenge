/** \file pow_core.h
\brief Find the hex string with the indicated difficulty.

This set of functions finds a hex string that has the indicated number of leading zeros
using the supplied token string.  The token is concatenated with a
suffix, and they are then passsed through a SHA256 hash.  The hash is tested to
see if it has a number of leading zeroes equal to the required difficulty.
This code automatically adjusts the suffix string length so that the solution
space will contain enough possible valid suffixes.

The resulting suffix and calculation time is returned as a 2-element vector of strings:
{suffix, elapsed_time}

The run_pow function should be called to initiate calculations:
run_pow(const char *token, int difficulty)
*/
#include <atomic>
#include <string>

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
 * \param token   Input string concatenated before the suffix.
 * \param difficulty Required leading hex zeros (nibbles).
 * \return PowResult. If not found within the search window,
 *         suffix is empty and seconds still reflects elapsed time.
 */
PowResult run_pow(const char *token, uint8_t difficulty);