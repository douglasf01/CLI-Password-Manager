#ifndef ENTRY_PASSWORD_H
#define ENTRY_PASSWORD_H

#include <string>
#include <vector>
#include <cstdint>

/**
* Represents a password with service, username, encrypted password and initialization vector (IV).
*/
class entryPassword {

private:
    std::string service;
    std::string username;
    std::string password;
    std::vector<uint8_t> iv;
public:
    static constexpr size_t AES_KEY_SIZE = 256 / 8; //AES-256
    static inline std::vector<uint8_t> key;
    entryPassword(std::string service, std::string username, std::string password,
    std::vector<uint8_t> iv);
    std::string get_service() const;
    std::string get_username() const;
    std::string get_password() const;
    std::vector<uint8_t> get_iv() const;
    void set_iv(std::vector<uint8_t> iv);
    void set_service(std::string service);
    void set_username(std::string username);
    void set_password(std::string password);
};

#endif