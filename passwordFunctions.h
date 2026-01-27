#ifndef PASSWORD_FUNCTIONS
#define PASSWORD_FUNCTIONS

#include <string>
#include <vector>
#include <cstdint>
#include "entryPassword.h"

/**
 * @brief Encrypts a password using AES.
 * @param input The password to be encrypted.
 * @param iv Unique initialization vector.
 * @param key The master key.
 * @return The encrypted password.
 */
std::string encrypt(const std::string& input, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);

/**
 * @brief Decrypts a password using AES.
 * @param cipher_text The encrypted password to be decrypted.
 * @param iv Unique initialization vector.
 * @param key The master key.
 * @return The decrypted password.
 */
std::string decrypt(const std::string& cipher_text, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);

/**
 * @brief Hashes the master password.
 * @param password The master password.
 * @return The hashed master password.
 */
std::string hashMasterPassword(const std::string& password);

/**
 * @brief Checks if a previously used master key exists and verifies it.
 *        If no key exists, prompts the user to create a new one.
 * @return True if the master password is correct or a new one is created, false otherwise.
 */
bool run_check();

/**
 * @brief Adds a new password entry by encrypting the password and creating an entryPassword object.
 * @param service The service associated with the password.
 * @param username The username associated with the password.
 * @param password The password to be encrypted and stored.
 * @param key The master key used to encrypt the password.
 * @return An entryPassword object containing the encrypted password and IV.
 */
entryPassword add_password(std::string service, std::string username, std::string password, std::vector<uint8_t>& key);

/**
 * @brief Decrypts and returns the password stored in an entryPassword object.
 * @param stored_pass The entryPassword object containing the encrypted password and IV.
 * @return The decrypted password.
 */
std::string reveal_password(entryPassword stored_pass);

/**
 * @brief Displays the main menu options for the password manager CLI.
 */
void display_menu();

/**
 * @brief Writes a vector of entryPassword objects to a file.
 * @param entries The vector of entryPassword objects to write to the file.
 * @param filename The name of the file to write to.
 */
void writeToFile(const std::vector<entryPassword>& entries, const std::string& filename);

/**
 * @brief Checks if a file exists and is accessible.
 * @param filename The name of the file to check.
 * @return True if the file exists and is accessible, false otherwise.
 */
bool fileExists(const std::string& filename);

/**
 * @brief Reads a vector of entryPassword objects from a file.
 * @param filename The name of the file to read from.
 * @return A vector of entryPassword objects.
 */
std::vector<entryPassword> readFromFile(const std::string& filename);

/**
 * @brief Displays a list of stored passwords after decrypting them.
 * @param entries Saved entryPasswords objects for display.
 */
void view_passwords(const std::vector<entryPassword>& entries);

/**
 * @brief Removes a password entry from the vector of entryPassword objects.
 * @param entries The vector of entryPassword objects.
 * @param index The index of the entry to remove.
 */
void remove_password(std::vector<entryPassword>& entries, int index);

#endif