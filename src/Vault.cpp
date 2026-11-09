#include "Vault.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/misc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>

namespace {

using CryptoPP::byte;
using CryptoPP::SecByteBlock;

constexpr char kMagic[4] = {'P', 'W', 'M', 'V'};
constexpr byte kVersion = 1;
constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kIvSize = 12;
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kHeaderSize = sizeof(kMagic) + 1 + 4 + kSaltSize;
constexpr std::uint32_t kMinIterations = 1000;
constexpr std::uint32_t kMaxIterations = 10000000;

void putU32(std::string& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xFF));
    }
}

std::uint32_t getU32(const std::string& in, std::size_t& pos) {
    if (in.size() - pos < 4) {
        throw VaultError("Vault data is truncated.");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8) | static_cast<byte>(in[pos++]);
    }
    return value;
}

std::string getField(const std::string& in, std::size_t& pos) {
    const std::uint32_t length = getU32(in, pos);
    if (in.size() - pos < length) {
        throw VaultError("Vault data is truncated.");
    }
    std::string field = in.substr(pos, length);
    pos += length;
    return field;
}

void putField(std::string& out, const std::string& field) {
    putU32(out, static_cast<std::uint32_t>(field.size()));
    out += field;
}

const byte* bytes(const std::string& text) {
    return reinterpret_cast<const byte*>(text.data());
}

SecByteBlock deriveKey(const std::string& masterPassword, const SecByteBlock& salt,
                       std::uint32_t iterations) {
    SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, key.size(), 0, bytes(masterPassword), masterPassword.size(),
                     salt, salt.size(), iterations);
    return key;
}

std::string buildHeader(std::uint32_t iterations, const SecByteBlock& salt) {
    std::string header(kMagic, sizeof(kMagic));
    header.push_back(static_cast<char>(kVersion));
    putU32(header, iterations);
    header.append(reinterpret_cast<const char*>(salt.data()), salt.size());
    return header;
}

// Writes to a temporary file with 0600 permissions, then renames it over the
// old vault so a crash never leaves a half written vault behind.
void writeFileAtomically(const std::string& path, const std::string& data) {
    const std::string tempPath = path + ".tmp";
    const int fd = ::open(tempPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        throw VaultError("Can not write " + tempPath + ": " + std::strerror(errno));
    }
    ::fchmod(fd, 0600);
    std::size_t written = 0;
    while (written < data.size()) {
        const ssize_t n = ::write(fd, data.data() + written, data.size() - written);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            const int error = errno;
            ::close(fd);
            ::unlink(tempPath.c_str());
            errno = error;
            throw VaultError("Can not write " + tempPath + ": " + std::strerror(errno));
        }
        written += static_cast<std::size_t>(n);
    }
    const bool ok = ::fsync(fd) == 0;
    if (::close(fd) != 0 || !ok || std::rename(tempPath.c_str(), path.c_str()) != 0) {
        const int error = errno;
        ::unlink(tempPath.c_str());
        errno = error;
        throw VaultError("Can not save " + path + ": " + std::strerror(errno));
    }
}

}  // namespace

Vault::Vault(std::string path, std::uint32_t iterations, SecByteBlock salt, SecByteBlock key)
    : path_(std::move(path)), iterations_(iterations), salt_(std::move(salt)), key_(std::move(key)) {}

Vault::~Vault() {
    for (PasswordEntry& entry : entries_) {
        wipe(entry.service);
        wipe(entry.username);
        wipe(entry.password);
    }
}

Vault Vault::create(const std::string& path, const std::string& masterPassword,
                    std::uint32_t iterations) {
    if (iterations < kMinIterations || iterations > kMaxIterations) {
        throw VaultError("Iteration count is out of range.");
    }
    SecByteBlock salt(kSaltSize);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(salt, salt.size());
    SecByteBlock key = deriveKey(masterPassword, salt, iterations);
    Vault vault(path, iterations, std::move(salt), std::move(key));
    vault.save();
    return vault;
}

std::optional<Vault> Vault::open(const std::string& path, const std::string& masterPassword) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw VaultError("Can not open " + path + ".");
    }
    const std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    if (data.size() < kHeaderSize + kIvSize + kTagSize ||
        data.compare(0, sizeof(kMagic), kMagic, sizeof(kMagic)) != 0) {
        throw VaultError(path + " is not a vault file.");
    }
    if (static_cast<byte>(data[sizeof(kMagic)]) != kVersion) {
        throw VaultError(path + " uses an unknown vault version.");
    }
    std::size_t pos = sizeof(kMagic) + 1;
    const std::uint32_t iterations = getU32(data, pos);
    if (iterations < kMinIterations || iterations > kMaxIterations) {
        throw VaultError(path + " has an invalid iteration count.");
    }
    SecByteBlock salt(bytes(data) + pos, kSaltSize);

    const byte* iv = bytes(data) + kHeaderSize;
    const byte* cipherText = iv + kIvSize;
    const std::size_t cipherSize = data.size() - kHeaderSize - kIvSize - kTagSize;
    const byte* tag = cipherText + cipherSize;

    SecByteBlock key = deriveKey(masterPassword, salt, iterations);
    SecByteBlock plain(cipherSize);
    CryptoPP::GCM<CryptoPP::AES>::Decryption gcm;
    gcm.SetKeyWithIV(key, key.size(), iv, kIvSize);
    if (!gcm.DecryptAndVerify(plain, tag, kTagSize, iv, kIvSize, bytes(data), kHeaderSize,
                              cipherText, cipherSize)) {
        return std::nullopt;
    }

    Vault vault(path, iterations, std::move(salt), std::move(key));
    std::string plainText(reinterpret_cast<const char*>(plain.data()), plain.size());
    vault.entries_ = parseEntries(plainText);
    wipe(plainText);
    return vault;
}

void Vault::save() const {
    std::string plainText = serializeEntries(entries_);

    SecByteBlock iv(kIvSize);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, iv.size());

    const std::string header = buildHeader(iterations_, salt_);
    std::string out = header;
    out.append(reinterpret_cast<const char*>(iv.data()), iv.size());
    out.resize(out.size() + plainText.size() + kTagSize);
    byte* cipherText = reinterpret_cast<byte*>(&out[kHeaderSize + kIvSize]);

    CryptoPP::GCM<CryptoPP::AES>::Encryption gcm;
    gcm.SetKeyWithIV(key_, key_.size(), iv, iv.size());
    gcm.EncryptAndAuthenticate(cipherText, cipherText + plainText.size(), kTagSize, iv, kIvSize,
                               bytes(header), header.size(), bytes(plainText), plainText.size());
    wipe(plainText);

    writeFileAtomically(path_, out);
}

std::string serializeEntries(const std::vector<PasswordEntry>& entries) {
    std::size_t total = 4;
    for (const PasswordEntry& e : entries) {
        total += 12 + e.service.size() + e.username.size() + e.password.size();
    }
    std::string out;
    out.reserve(total);  // One allocation, so no stray copies of secrets are left behind.
    putU32(out, static_cast<std::uint32_t>(entries.size()));
    for (const PasswordEntry& e : entries) {
        putField(out, e.service);
        putField(out, e.username);
        putField(out, e.password);
    }
    return out;
}

std::vector<PasswordEntry> parseEntries(const std::string& data) {
    std::size_t pos = 0;
    const std::uint32_t count = getU32(data, pos);
    std::vector<PasswordEntry> entries;
    for (std::uint32_t i = 0; i < count; ++i) {
        PasswordEntry e;
        e.service = getField(data, pos);
        e.username = getField(data, pos);
        e.password = getField(data, pos);
        entries.push_back(std::move(e));
    }
    if (pos != data.size()) {
        throw VaultError("Vault data has extra bytes.");
    }
    return entries;
}

std::string generatePassword(std::size_t length) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+";
    CryptoPP::AutoSeededRandomPool rng;
    std::string password;
    password.reserve(length);
    for (std::size_t i = 0; i < length; ++i) {
        password += chars[rng.GenerateWord32(0, static_cast<CryptoPP::word32>(chars.size() - 1))];
    }
    return password;
}

void wipe(std::string& text) {
    CryptoPP::SecureWipeBuffer(text.data(), text.size());
    text.clear();
}
