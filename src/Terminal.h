#ifndef TERMINAL_H
#define TERMINAL_H

#include <optional>
#include <string>

// Prints the prompt and reads one line. Returns nothing on end of input.
std::optional<std::string> readLine(const std::string& prompt);

// Like readLine, but turns off echo when stdin is a terminal.
std::optional<std::string> readSecret(const std::string& prompt);

#endif
