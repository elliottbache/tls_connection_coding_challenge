/** \file pow_core.h
\brief Find the hex string with the indicated difficulty.

This set of functions finds a hex string that has the indicated number of leading zeros
using the supplied authdata string.  The SHA1 context is initialized with the authdata
(SHA1_Init(...)), then a copy of this context is updated with each suffix
(SHA1_Update(...)), before finalizing (SHA1_Final(...)).  The hash is tested to
see if it has a number of leading zeroes equal to the required difficulty.
This code automatically adjusts the suffix string length so that the solution
space will contain enough possible valid suffixes.

The resulting suffix and calculation time is returned as a 2-element vector of strings:
{suffix, elapsed_time}

The run_pow function should be called to initiate calculations:
run_pow(const char *authdata, int difficulty)
*/
#pragma once
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
 * \post res.found ⇒ suffix satisfies predicate
 *
 * \param authdata   Input string concatenated before the suffix.
 * \param difficulty Required leading hex zeros (nibbles).
 * \return PowResult. If not found within the search window,
 *         suffix is empty and seconds still reflects elapsed time.
 */
PowResult run_pow(const char *authdata, uint8_t difficulty);