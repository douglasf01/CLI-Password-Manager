#include "Strength.h"

#include <cmath>

namespace {

constexpr std::size_t kMinLength = 8;

}  // namespace

Strength rateStrength(const std::string& password) {
    bool lower = false, upper = false, digit = false, other = false;
    std::size_t length = 0;
    for (const char c : password) {
        const auto u = static_cast<unsigned char>(c);
        if ((u & 0xC0) == 0x80) {
            continue;  // A UTF-8 continuation byte, not a new character.
        }
        ++length;
        if (u >= 'a' && u <= 'z') {
            lower = true;
        } else if (u >= 'A' && u <= 'Z') {
            upper = true;
        } else if (u >= '0' && u <= '9') {
            digit = true;
        } else {
            other = true;
        }
    }
    const int pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (other ? 33 : 0);
    const double bits = pool > 0 ? static_cast<double>(length) * std::log2(pool) : 0.0;

    StrengthLevel level = StrengthLevel::Strong;
    if (length < kMinLength || bits < 45) {
        level = StrengthLevel::Weak;
    } else if (bits < 70) {
        level = StrengthLevel::Fair;
    } else if (bits < 100) {
        level = StrengthLevel::Good;
    }
    return {bits, level};
}

const char* strengthName(StrengthLevel level) {
    switch (level) {
        case StrengthLevel::Weak: return "weak";
        case StrengthLevel::Fair: return "fair";
        case StrengthLevel::Good: return "good";
        case StrengthLevel::Strong: return "strong";
    }
    return "";
}
