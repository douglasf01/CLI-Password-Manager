#include "Ui.h"

#include "Strength.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>

namespace {

bool useColor = false;

// SGR color codes.
const char* const kAccent = "1;36";
const char* const kBold = "1";
const char* const kDim = "2";
const char* const kGreen = "32";
const char* const kStrongGreen = "1;32";
const char* const kYellow = "33";
const char* const kRed = "31";

constexpr std::size_t kLabelWidth = 11;
constexpr std::size_t kMeterCells = 10;
constexpr double kBitsPerCell = 12.0;

std::string paint(const char* code, const std::string& text) {
    if (!useColor) {
        return text;
    }
    return std::string("\033[") + code + "m" + text + "\033[0m";
}

std::string repeat(const std::string& piece, std::size_t count) {
    std::string out;
    for (std::size_t i = 0; i < count; ++i) {
        out += piece;
    }
    return out;
}

// Splits UTF-8 text into code points, each kept as its own small string.
std::vector<std::string> codePoints(const std::string& text) {
    std::vector<std::string> out;
    for (const char c : text) {
        const bool continuation = (static_cast<unsigned char>(c) & 0xC0) == 0x80;
        if (continuation && !out.empty()) {
            out.back() += c;
        } else {
            out.emplace_back(1, c);
        }
    }
    return out;
}

// True for ASCII and C1 control characters, which could move the cursor or
// change colors if printed as they are.
bool isControl(const std::string& ch) {
    const auto first = static_cast<unsigned char>(ch[0]);
    if (first < 0x20 || first == 0x7F) {
        return true;
    }
    return first == 0xC2 && ch.size() > 1 && static_cast<unsigned char>(ch[1]) < 0xA0;
}

void printLine(const std::string& symbol, const char* color, const std::string& message) {
    std::cout << "  " << paint(color, symbol + " " + message) << "\n";
}

std::string label(const std::string& text) {
    return paint(kDim, ui::fit(text, kLabelWidth));
}

}  // namespace

namespace ui {

void init() {
    const char* noColor = std::getenv("NO_COLOR");
    const char* term = std::getenv("TERM");
    useColor = isatty(STDOUT_FILENO) && !(noColor && *noColor) &&
               !(term && std::strcmp(term, "dumb") == 0);
}

void banner(const std::string& vaultPath) {
    const std::string lock[] = {" ╭─╮ ", "┌┴─┴┐", "│ ● │", "└───┘"};
    const std::string text[] = {
        "",
        paint(kAccent, "pwm") + paint(kDim, "  password manager"),
        paint(kDim, "AES-256-GCM · PBKDF2-SHA256"),
        paint(kDim, "vault ") + clean(vaultPath, 60),
    };
    std::cout << "\n";
    for (std::size_t i = 0; i < 4; ++i) {
        std::cout << "   " << paint(kAccent, lock[i]) << (text[i].empty() ? "" : "   " + text[i])
                  << "\n";
    }
    std::cout << "\n";
}

void menu(const std::string& vaultPath, std::size_t entryCount) {
    struct Item {
        const char* key;
        const char* name;
    };
    const Item items[] = {{"1", "Add"},    {"2", "List"},   {"3", "Search"},
                          {"4", "Reveal"}, {"5", "Remove"}, {"6", "Lock and exit"}};
    constexpr std::size_t kColumns = 3;
    constexpr std::size_t kCellWidth = 15;
    constexpr std::size_t kInner = 1 + kColumns * kCellWidth + 1;

    const std::string count =
        std::to_string(entryCount) + (entryCount == 1 ? " entry" : " entries");
    const std::string path = clean(vaultPath, kInner - displayWidth(count) - 8);
    const std::size_t titleWidth = displayWidth(path) + displayWidth(count) + 5;

    std::cout << "  " << paint(kDim, "╭─") << " " << paint(kBold, path) << paint(kDim, " · ")
              << paint(kAccent, count) << " " << paint(kDim, repeat("─", kInner - 1 - titleWidth) + "╮")
              << "\n";
    for (std::size_t row = 0; row < std::size(items) / kColumns; ++row) {
        std::cout << "  " << paint(kDim, "│") << " ";
        for (std::size_t col = 0; col < kColumns; ++col) {
            const Item& item = items[row * kColumns + col];
            std::cout << paint(kAccent, item.key) << " " << fit(item.name, kCellWidth - 2);
        }
        std::cout << " " << paint(kDim, "│") << "\n";
    }
    std::cout << "  " << paint(kDim, "╰" + repeat("─", kInner) + "╯") << "\n";
}

std::string prompt(const std::string& text) {
    return "  " + paint(kAccent, "›") + " " + text + ": ";
}

void info(const std::string& message) {
    std::cout << "  " << paint(kDim, message) << "\n";
}

void success(const std::string& message) {
    printLine("✓", kGreen, message);
}

void warning(const std::string& message) {
    printLine("!", kYellow, message);
}

void error(const std::string& message) {
    printLine("✗", kRed, message);
}

void entryTable(const std::vector<PasswordEntry>& entries, const std::vector<std::size_t>& rows) {
    const std::string mask = "••••••••";
    std::size_t widths[] = {1, displayWidth("Service"), displayWidth("Username"),
                            displayWidth("Password")};
    for (const std::size_t i : rows) {
        widths[0] = std::max(widths[0], std::to_string(i + 1).size());
        widths[1] = std::max(widths[1], std::min<std::size_t>(displayWidth(entries[i].service), 22));
        widths[2] = std::max(widths[2], std::min<std::size_t>(displayWidth(entries[i].username), 28));
    }

    auto border = [&](const char* left, const char* middle, const char* right) {
        std::string line = left;
        for (std::size_t c = 0; c < 4; ++c) {
            line += repeat("─", widths[c] + 2) + (c < 3 ? middle : right);
        }
        std::cout << "  " << paint(kDim, line) << "\n";
    };
    auto row = [&](const std::string (&cells)[4], const char* const (&colors)[4]) {
        const std::string bar = paint(kDim, "│");
        std::cout << "  " << bar;
        for (std::size_t c = 0; c < 4; ++c) {
            // The number column is right aligned, the others left aligned.
            const std::string text = c == 0 ? std::string(widths[0] - cells[0].size(), ' ') + cells[0]
                                            : fit(cells[c], widths[c]);
            std::cout << " " << (colors[c] ? paint(colors[c], text) : text) << " " << bar;
        }
        std::cout << "\n";
    };

    border("╭", "┬", "╮");
    row({"#", "Service", "Username", "Password"}, {kAccent, kAccent, kAccent, kAccent});
    border("├", "┼", "┤");
    for (const std::size_t i : rows) {
        row({std::to_string(i + 1), entries[i].service, entries[i].username, mask},
            {kAccent, kBold, nullptr, kDim});
    }
    border("╰", "┴", "╯");
}

void revealPassword(const PasswordEntry& entry) {
    std::cout << "  " << label("Service") << paint(kBold, clean(entry.service, 60)) << "\n"
              << "  " << label("Username") << clean(entry.username, 60) << "\n"
              << "  " << label("Password") << paint(kYellow, clean(entry.password, 200)) << "\n";
    info("It stays visible in this terminal until you clear it.");
}

void generatedPassword(const std::string& password) {
    std::cout << "  " << label("Generated") << paint(kAccent, password) << "\n";
}

void strengthMeter(const std::string& password) {
    const Strength strength = rateStrength(password);
    const char* color = kRed;
    switch (strength.level) {
        case StrengthLevel::Weak: color = kRed; break;
        case StrengthLevel::Fair: color = kYellow; break;
        case StrengthLevel::Good: color = kGreen; break;
        case StrengthLevel::Strong: color = kStrongGreen; break;
    }
    const auto filled = std::clamp<std::size_t>(
        static_cast<std::size_t>(std::lround(strength.bits / kBitsPerCell)), 1, kMeterCells);
    std::cout << "  " << label("Strength") << paint(color, repeat("█", filled))
              << paint(kDim, repeat("░", kMeterCells - filled)) << " "
              << paint(color, strengthName(strength.level))
              << paint(kDim, " · about " + std::to_string(std::lround(strength.bits)) + " bits")
              << "\n";
}

std::size_t displayWidth(const std::string& text) {
    return codePoints(text).size();
}

std::string clean(const std::string& text, std::size_t maxWidth) {
    const std::vector<std::string> chars = codePoints(text);
    const bool cut = chars.size() > maxWidth;
    const std::size_t keep = cut ? (maxWidth > 0 ? maxWidth - 1 : 0) : chars.size();
    std::string out;
    for (std::size_t i = 0; i < keep; ++i) {
        out += isControl(chars[i]) ? "?" : chars[i];
    }
    if (cut && maxWidth > 0) {
        out += "…";
    }
    return out;
}

std::string fit(const std::string& text, std::size_t width) {
    std::string out = clean(text, width);
    out.append(width - displayWidth(out), ' ');
    return out;
}

}  // namespace ui
