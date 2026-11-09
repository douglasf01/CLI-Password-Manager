// Small self contained tests for the vault and the text helpers. Run with `ctest` or directly.
#include "Strength.h"
#include "Ui.h"
#include "Vault.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

namespace {

int failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; \
            ++failures;                                                          \
        }                                                                        \
    } while (0)

// Low iteration count keeps the tests fast. The real program uses 600000.
constexpr std::uint32_t kTestIterations = 1000;
const std::string kMaster = "correct horse battery staple";

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void writeFile(const fs::path& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << data;
}

std::vector<PasswordEntry> sampleEntries() {
    return {
        {"mail", "alice@example.com", "s3cret-pass"},
        {"bank, main account", "bob,smith", "pa,ss\nword with \"quotes\""},
        {"", "", std::string("zero\0byte", 9)},
    };
}

bool sameEntries(const std::vector<PasswordEntry>& a, const std::vector<PasswordEntry>& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i].service != b[i].service || a[i].username != b[i].username ||
            a[i].password != b[i].password) {
            return false;
        }
    }
    return true;
}

void testRoundTrip(const fs::path& dir) {
    const std::string path = (dir / "roundtrip.dat").string();
    Vault vault = Vault::create(path, kMaster, kTestIterations);
    vault.entries() = sampleEntries();
    vault.save();

    std::optional<Vault> opened = Vault::open(path, kMaster);
    CHECK(opened.has_value());
    if (opened) {
        CHECK(sameEntries(opened->entries(), sampleEntries()));
    }
    CHECK((fs::status(path).permissions() & fs::perms::all) ==
          (fs::perms::owner_read | fs::perms::owner_write));

    const std::string raw = readFile(path);
    CHECK(raw.find("s3cret-pass") == std::string::npos);
    CHECK(raw.find("alice@example.com") == std::string::npos);
}

void testWrongPassword(const fs::path& dir) {
    const std::string path = (dir / "wrong.dat").string();
    Vault vault = Vault::create(path, kMaster, kTestIterations);
    vault.entries() = sampleEntries();
    vault.save();
    CHECK(!Vault::open(path, "not the password").has_value());
    CHECK(!Vault::open(path, "").has_value());
}

void testTamperedFile(const fs::path& dir) {
    const std::string path = (dir / "tamper.dat").string();
    Vault vault = Vault::create(path, kMaster, kTestIterations);
    vault.entries() = sampleEntries();
    vault.save();
    const std::string original = readFile(path);

    // Flip one bit in each byte position in turn: header, salt, IV, ciphertext, tag.
    for (std::size_t i = 5; i < original.size(); ++i) {
        std::string changed = original;
        changed[i] = static_cast<char>(changed[i] ^ 0x01);
        writeFile(path, changed);
        try {
            CHECK(!Vault::open(path, kMaster).has_value());
        } catch (const VaultError&) {
            // Also fine: the header was rejected before decrypting.
        }
    }

    writeFile(path, original.substr(0, original.size() - 1));
    CHECK(!Vault::open(path, kMaster).has_value());

    writeFile(path, "not a vault");
    bool threw = false;
    try {
        Vault::open(path, kMaster);
    } catch (const VaultError&) {
        threw = true;
    }
    CHECK(threw);
}

void testFreshSaltAndIv(const fs::path& dir) {
    const std::string pathA = (dir / "a.dat").string();
    const std::string pathB = (dir / "b.dat").string();
    Vault a = Vault::create(pathA, kMaster, kTestIterations);
    Vault b = Vault::create(pathB, kMaster, kTestIterations);
    const std::string fileA = readFile(pathA);
    const std::string fileB = readFile(pathB);
    // Salt is bytes 9 to 24. Same password, different vaults: different salts.
    CHECK(fileA.substr(9, 16) != fileB.substr(9, 16));

    a.entries() = sampleEntries();
    a.save();
    const std::string first = readFile(pathA);
    a.save();
    const std::string second = readFile(pathA);
    // Same content saved twice: same salt, new IV (bytes 25 to 36), new ciphertext.
    CHECK(first.substr(9, 16) == second.substr(9, 16));
    CHECK(first.substr(25, 12) != second.substr(25, 12));
    CHECK(first.substr(37) != second.substr(37));
}

void testSerialization() {
    CHECK(sameEntries(parseEntries(serializeEntries(sampleEntries())), sampleEntries()));
    CHECK(parseEntries(serializeEntries({})).empty());
    bool threw = false;
    try {
        parseEntries(std::string("\x00\x00\x00\x05", 4));
    } catch (const VaultError&) {
        threw = true;
    }
    CHECK(threw);
}

void testGeneratePassword() {
    const std::string a = generatePassword(20);
    CHECK(a.size() == 20);
    CHECK(a != generatePassword(20));
}

void testStrength() {
    CHECK(rateStrength("").level == StrengthLevel::Weak);
    CHECK(rateStrength("Ab1!xyz").level == StrengthLevel::Weak);  // Too short.
    CHECK(rateStrength("abcdefgh").level == StrengthLevel::Weak);
    CHECK(rateStrength("abcdefghijkl").level == StrengthLevel::Fair);
    CHECK(rateStrength("My$ecretPass1").level == StrengthLevel::Good);
    CHECK(rateStrength(generatePassword(20)).level == StrengthLevel::Strong);
    // Same length, more character types: more bits.
    CHECK(rateStrength("aaaaaaaaaa").bits < rateStrength("aaaaaAAAA1").bits);
    // A multi byte character counts once.
    CHECK(rateStrength("\xC3\xA9").bits == rateStrength("!").bits);
    CHECK(std::string(strengthName(StrengthLevel::Strong)) == "strong");
}

void testTextHelpers() {
    CHECK(ui::displayWidth("github") == 6);
    CHECK(ui::displayWidth("caf\xC3\xA9") == 4);
    CHECK(ui::fit("abc", 5) == "abc  ");
    CHECK(ui::fit("abcdef", 4) == "abc\xE2\x80\xA6");
    CHECK(ui::displayWidth(ui::fit("caf\xC3\xA9 au lait", 6)) == 6);
    CHECK(ui::clean("abc", 10) == "abc");
    // Escape sequences and newlines in stored data must not reach the terminal.
    CHECK(ui::clean("a\x1b[31mb\n", 20) == "a?[31mb?");
    CHECK(ui::clean("x\xC2\x9By", 20) == "x?y");
}

}  // namespace

int main() {
    const fs::path dir = fs::temp_directory_path() / ("vault-tests-" + std::to_string(::getpid()));
    fs::create_directories(dir);

    testRoundTrip(dir);
    testWrongPassword(dir);
    testTamperedFile(dir);
    testFreshSaltAndIv(dir);
    testSerialization();
    testGeneratePassword();
    testStrength();
    testTextHelpers();

    fs::remove_all(dir);
    if (failures == 0) {
        std::cout << "All tests passed.\n";
        return 0;
    }
    std::cerr << failures << " check(s) failed.\n";
    return 1;
}
