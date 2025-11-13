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

    std::vector<std::string> outputs = run_pow(authdata, difficulty);

    if (outputs[0].empty())
    {
        std::cerr << "No result found.\n";
    }
    else
    {
        std::cout << "RESULT:" << outputs[0] << "\n";
        std::cout << "Time: " << outputs[1] << " seconds\n";
    }

    return 0;
}
