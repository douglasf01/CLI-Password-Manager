#ifndef VAULT_H
#define VAULT_H

#include "PasswordEntry.h"

#include <cryptopp/secblock.h>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Thrown when the vault file can not be read or written, or is not a vault file.
class VaultError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// An encrypted file holding all password entries.
//
// File layout (all numbers big endian):
//   "PWMV" | version (1 byte) | PBKDF2 iterations (4 bytes) | salt (16 bytes)
//   | IV (12 bytes) | AES-256-GCM ciphertext | GCM tag (16 bytes)
// The bytes before the IV are also checked by the GCM tag.
class Vault {
public:
    static constexpr std::uint32_t kDefaultIterations = 600000;

    // Creates a new vault with a fresh random salt and saves it (empty) to disk.
    static Vault create(const std::string& path, const std::string& masterPassword,
                        std::uint32_t iterations = kDefaultIterations);

    // Opens an existing vault. Returns nothing if the master password is wrong
    // or the file was changed. Throws VaultError if the file is unreadable.
    static std::optional<Vault> open(const std::string& path, const std::string& masterPassword);

    // Encrypts all entries with a fresh random IV and replaces the file.
    void save() const;

    std::vector<PasswordEntry>& entries() { return entries_; }
    const std::vector<PasswordEntry>& entries() const { return entries_; }

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    Vault(Vault&&) = default;
    Vault& operator=(Vault&&) = default;
    ~Vault();

private:
    Vault(std::string path, std::uint32_t iterations, CryptoPP::SecByteBlock salt,
          CryptoPP::SecByteBlock key);

    std::string path_;
    std::uint32_t iterations_;
    CryptoPP::SecByteBlock salt_;
    CryptoPP::SecByteBlock key_;
    std::vector<PasswordEntry> entries_;
};

// Turns entries into bytes and back. Each field is stored with its length,
// so any character (commas, newlines, zero bytes) is safe.
std::string serializeEntries(const std::vector<PasswordEntry>& entries);
std::vector<PasswordEntry> parseEntries(const std::string& data);

// Returns a random password made of letters, digits and symbols.
std::string generatePassword(std::size_t length);

// Overwrites the string's memory with zeros, then empties it.
void wipe(std::string& text);

#endif
