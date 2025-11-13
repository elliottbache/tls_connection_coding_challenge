/** \brief Find the hex string with the indicated difficulty.

This file is an entry to the POW functions.
Syntax: pow_benchmark <authdata> <difficulty>
*/
#include <iostream>
#include <vector>
#include "pow_core.h"

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <authdata> <difficulty>\n";
        return 1;
    }

    const char *authdata = argv[1];
    int difficulty = std::stoi(argv[2]);

    PowResult outputs = run_pow(authdata, difficulty);

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
