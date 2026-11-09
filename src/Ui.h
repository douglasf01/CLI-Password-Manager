#ifndef UI_H
#define UI_H

#include "PasswordEntry.h"

#include <cstddef>
#include <string>
#include <vector>

// Everything that draws on the screen. Colors are used only when stdout is a
// terminal, NO_COLOR is not set and TERM is not "dumb".
namespace ui {

void init();

void banner(const std::string& vaultPath);
void menu(const std::string& vaultPath, std::size_t entryCount);

// Returns a styled prompt to pass to readLine or readSecret.
std::string prompt(const std::string& label);

void info(const std::string& message);
void success(const std::string& message);
void warning(const std::string& message);
void error(const std::string& message);

// Draws the given entries as a table. `rows` holds indexes into `entries`.
// Passwords are always masked here.
void entryTable(const std::vector<PasswordEntry>& entries, const std::vector<std::size_t>& rows);

void revealPassword(const PasswordEntry& entry);
void generatedPassword(const std::string& password);
void strengthMeter(const std::string& password);

// Number of characters the text takes on screen (one per UTF-8 code point).
std::size_t displayWidth(const std::string& text);

// Replaces control characters with "?" and cuts the text to at most
// `maxWidth` cells, ending with "…" when something was cut.
std::string clean(const std::string& text, std::size_t maxWidth);

// Like clean, then pads with spaces so the text fills exactly `width` cells.
std::string fit(const std::string& text, std::size_t width);

}  // namespace ui

#endif
