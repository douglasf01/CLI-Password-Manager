#include "Terminal.h"

#include <iostream>
#include <termios.h>
#include <unistd.h>

std::optional<std::string> readLine(const std::string& prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) {
        return std::nullopt;
    }
    return line;
}

std::optional<std::string> readSecret(const std::string& prompt) {
    termios oldSettings{};
    const bool isTerminal = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldSettings) == 0;
    if (isTerminal) {
        termios noEcho = oldSettings;
        noEcho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &noEcho);
    }

    std::optional<std::string> line = readLine(prompt);

    if (isTerminal) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldSettings);
        std::cout << "\n";
    }
    return line;
}
