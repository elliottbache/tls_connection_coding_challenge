/** \brief Find the hex string with the indicated trailing n_bits zeros.

This file is an entry to the WORK functions.
Syntax: work_challenge <token> <n_bits>
*/
#include <iostream>
#include <vector>
#include "work_core.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <token> <n_bits>\n";
        return 1;
    }

    const char *token = argv[1];
    uint8_t n_bits = std::stoi(argv[2]);

    WorkResult outputs = run_work(token, n_bits);

    if (outputs.suffix.empty())
    {
        std::cerr << "No result found.\n";
    }
    else
    {
        std::cout << "RESULT:" << outputs.suffix << "\n";
        std::cout << "Time: " << outputs.seconds << " seconds\n";
    }

    return 0;
}
