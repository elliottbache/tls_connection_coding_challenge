/** \file work_core.h
\brief Find the hex string with the indicated trailing n_bits zeros.

This set of functions finds a hex string that has the indicated number of trailing bit zeros
using the supplied token string.  The SHA256 context is initialized with the token
(SHA256_Init(...)), then a copy of this context is updated with each suffix
(SHA256_Update(...)), before finalizing (SHA256_Final(...)).  The hash is tested to
see if it has a number of trailing bit zeros equal to the required n_bits.
This code automatically adjusts the suffix string length so that the solution
space will contain enough possible valid suffixes.

The resulting suffix and calculation time is returned as a 2-element vector of strings:
{suffix, elapsed_time}

The run_work function should be called to initiate calculations:
run_work(const char *token, int n_bits)
*/
#pragma once
#include <atomic>
#include <string>

/**
 * \brief Struct to return results.
 *
 * Pair of (suffix, seconds).
 */
struct WorkResult
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
 * \param token Input string concatenated before the suffix.
 * \param n_bits Required trailing bit zeros.
 * \return WorkResult. If not found within the search window,
 *         suffix is empty and seconds still reflects elapsed time.
 */
WorkResult run_work(const char *token, uint8_t n_bits);