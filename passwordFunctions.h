#ifndef PASSWORD_FUNCTIONS
#define PASSWORD_FUNCTIONS

#include <string>
#include <vector>
#include <cstdint>
#include "entryPassword.h"

std::string decrypt(const std::string& cipher_text, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);
std::string encrypt(const std::string& input, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);
std::string hashMasterPassword(const std::string& password);
bool run_check();
entryPassword add_password(std::string service, std::string username, std::string password, std::vector<uint8_t>& key);
std::string reveal_password(entryPassword stored_pass);
void display_menu();
void writeToFile(const std::vector<entryPassword>& entries, const std::string& filename);
bool fileExists(const std::string& filename);
std::vector<entryPassword> readFromFile(const std::string& filename);
void view_passwords(const std::vector<entryPassword>& entries);
void remove_password(std::vector<entryPassword>& entries, int index);

#endif