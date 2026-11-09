#ifndef PASSWORD_ENTRY_H
#define PASSWORD_ENTRY_H

#include <string>

// One saved login. Fields are kept in plain text only while the vault is open.
struct PasswordEntry {
    std::string service;
    std::string username;
    std::string password;
};

#endif
