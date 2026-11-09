#ifndef STRENGTH_H
#define STRENGTH_H

#include <string>

enum class StrengthLevel { Weak, Fair, Good, Strong };

// A rough guess of how hard a password is to brute force.
struct Strength {
    double bits;  // length times log2 of the size of the character types used
    StrengthLevel level;
};

// Looks only at length and which character types appear (lower case, upper
// case, digits, others). It assumes the characters are random, so a real word
// with a digit on the end scores higher than it should. Treat it as a hint.
Strength rateStrength(const std::string& password);

const char* strengthName(StrengthLevel level);

#endif
