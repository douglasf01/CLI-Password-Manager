#include "entryPassword.h"

entryPassword::entryPassword(std::string service, std::string username, std::string password, std::vector<uint8_t> iv){
    this->service = service;
    this->username = username;
    this->password = password;
    this->iv = iv;
}
std::string entryPassword::get_service() const {
    return this->service;
}
std::string entryPassword::get_username() const {
    return this->username;
}
std::string entryPassword::get_password() const {
    return this->password;
}
std::vector<uint8_t> entryPassword::get_iv() const {
    return this->iv;
}
void entryPassword::set_iv(std::vector<uint8_t> iv) {
    this->iv = iv;
}
void entryPassword::set_service(std::string service) {
    this->service = service;
}
void entryPassword::set_username(std::string username) {
    this->username = username;
}
void entryPassword::set_password(std::string password) {
    this->password = password;
}