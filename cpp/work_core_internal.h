#pragma once
namespace work_internal
{
    /** \brief Maximum concatenated input size (token + suffix) fed to SHA-256.

        Increase if your token can be longer than this.
        \see run_work
         */
    constexpr size_t MAX_INPUT_SIZE = 256;

    /** \brief Character set to be used for creating suffix.
     */
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    /** \brief Length of charset */
    const size_t charset_size = sizeof(charset) - 1;

    // Determine suffix length so that keyspace ≥ 2^n_bits
    size_t determine_suffix_length(uint8_t n_bits);

    void generate_counter_string(uint64_t counter, unsigned char *output, size_t output_length);

    bool has_trailing_zeros(const uint8_t *digest, int bits_required);
}
