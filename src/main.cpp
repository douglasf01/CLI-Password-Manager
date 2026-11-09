#include "Terminal.h"
#include "Ui.h"
#include "Vault.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

namespace {

constexpr int kMaxTries = 3;
constexpr std::size_t kMinMasterLength = 8;
constexpr std::size_t kGeneratedLength = 20;

std::string vaultPath() {
    const char* fromEnv = std::getenv("PWM_VAULT");
    return (fromEnv && *fromEnv) ? fromEnv : "vault.dat";
}

std::optional<std::size_t> parseNumber(const std::string& text) {
    std::size_t value = 0;
    const char* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(text.data(), end, value);
    if (ec != std::errc() || ptr != end || text.empty()) {
        return std::nullopt;
    }
    return value;
}

std::string lowerCase(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::optional<Vault> createVault(const std::string& path) {
    ui::info("No vault found. Creating a new one.");
    while (true) {
        std::optional<std::string> first = readSecret(ui::prompt("New master password"));
        if (!first) {
            return std::nullopt;
        }
        if (first->size() < kMinMasterLength) {
            ui::warning("Use at least " + std::to_string(kMinMasterLength) + " characters.");
            wipe(*first);
            continue;
        }
        ui::strengthMeter(*first);
        std::optional<std::string> second = readSecret(ui::prompt("Repeat master password"));
        if (!second) {
            wipe(*first);
            return std::nullopt;
        }
        const bool match = *first == *second;
        wipe(*second);
        if (!match) {
            ui::error("Passwords do not match. Try again.");
            wipe(*first);
            continue;
        }
        Vault vault = Vault::create(path, *first);
        wipe(*first);
        ui::success("Vault created.");
        return vault;
    }
}

std::optional<Vault> unlockVault(const std::string& path) {
    for (int attempt = 1; attempt <= kMaxTries; ++attempt) {
        std::optional<std::string> master = readSecret(ui::prompt("Master password"));
        if (!master) {
            return std::nullopt;
        }
        std::optional<Vault> vault = Vault::open(path, *master);
        wipe(*master);
        if (vault) {
            ui::success("Vault unlocked.");
            return vault;
        }
        ui::error("Wrong master password, or the vault file was changed.");
    }
    ui::error("Too many wrong tries.");
    return std::nullopt;
}

// Asks for an entry number and stores its index in `index` if it is valid.
// Returns false only at the end of input.
bool pickEntry(const Vault& vault, const std::string& action, std::optional<std::size_t>& index) {
    if (vault.entries().empty()) {
        ui::warning("The vault is empty.");
        return true;
    }
    std::optional<std::string> input = readLine(ui::prompt("Number of the entry to " + action));
    if (!input) {
        return false;
    }
    std::optional<std::size_t> number = parseNumber(*input);
    if (!number || *number < 1 || *number > vault.entries().size()) {
        ui::error("No entry with that number.");
        return true;
    }
    index = *number - 1;
    return true;
}

bool addEntry(Vault& vault) {
    PasswordEntry entry;
    std::optional<std::string> service = readLine(ui::prompt("Service"));
    std::optional<std::string> username =
        service ? readLine(ui::prompt("Username or email")) : std::nullopt;
    std::optional<std::string> password =
        username ? readSecret(ui::prompt("Password (empty to generate)")) : std::nullopt;
    if (!password) {
        return false;
    }
    entry.service = std::move(*service);
    entry.username = std::move(*username);
    entry.password = std::move(*password);
    if (entry.password.empty()) {
        entry.password = generatePassword(kGeneratedLength);
        ui::generatedPassword(entry.password);
    }
    ui::strengthMeter(entry.password);
    vault.entries().push_back(std::move(entry));
    vault.save();
    ui::success("Saved " + ui::clean(vault.entries().back().service, 30) + ".");
    return true;
}

void listEntries(const Vault& vault) {
    if (vault.entries().empty()) {
        ui::info("No passwords saved yet. Choose 1 to add one.");
        return;
    }
    std::vector<std::size_t> rows(vault.entries().size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        rows[i] = i;
    }
    ui::entryTable(vault.entries(), rows);
}

bool searchEntries(const Vault& vault) {
    std::optional<std::string> query = readLine(ui::prompt("Search for service"));
    if (!query) {
        return false;
    }
    const std::string needle = lowerCase(*query);
    std::vector<std::size_t> rows;
    for (std::size_t i = 0; i < vault.entries().size(); ++i) {
        if (lowerCase(vault.entries()[i].service).find(needle) != std::string::npos) {
            rows.push_back(i);
        }
    }
    if (rows.empty()) {
        ui::warning("No service matches \"" + ui::clean(*query, 30) + "\".");
    } else {
        ui::entryTable(vault.entries(), rows);
    }
    return true;
}

bool revealEntry(const Vault& vault) {
    std::optional<std::size_t> index;
    if (!pickEntry(vault, "reveal", index)) {
        return false;
    }
    if (index) {
        ui::revealPassword(vault.entries()[*index]);
    }
    return true;
}

bool removeEntry(Vault& vault) {
    std::optional<std::size_t> index;
    if (!pickEntry(vault, "remove", index)) {
        return false;
    }
    if (index) {
        auto it = vault.entries().begin() + static_cast<std::ptrdiff_t>(*index);
        const std::string name = ui::clean(it->service, 30);
        wipe(it->password);
        vault.entries().erase(it);
        vault.save();
        ui::success("Removed " + name + ".");
    }
    return true;
}

void runMenu(Vault& vault, const std::string& path) {
    while (true) {
        std::cout << "\n";
        ui::menu(path, vault.entries().size());
        std::optional<std::string> choice = readLine(ui::prompt("Choice"));
        if (!choice || *choice == "6" || *choice == "q") {
            return;
        }
        std::cout << "\n";
        bool keepGoing = true;
        if (*choice == "1") {
            keepGoing = addEntry(vault);
        } else if (*choice == "2") {
            listEntries(vault);
        } else if (*choice == "3") {
            keepGoing = searchEntries(vault);
        } else if (*choice == "4") {
            keepGoing = revealEntry(vault);
        } else if (*choice == "5") {
            keepGoing = removeEntry(vault);
        } else {
            ui::warning("Please enter a number from 1 to 6.");
        }
        if (!keepGoing) {
            return;
        }
    }
}

}  // namespace

int main() {
    ui::init();
    try {
        const std::string path = vaultPath();
        ui::banner(path);
        std::optional<Vault> vault =
            std::filesystem::exists(path) ? unlockVault(path) : createVault(path);
        if (!vault) {
            return 1;
        }
        runMenu(*vault, path);
        std::cout << "\n";
        ui::info("Vault locked. Goodbye.");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
