#include "passwordFunctions.h"
#include <iostream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <filesystem>

std::string decrypt(const std::string& cipher_text, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key) {
    std::string plain_text;

    auto aes = CryptoPP::AES::Decryption(key.data(), key.size());
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Decryption(aes, iv.data());

    CryptoPP::StringSource ss(
        cipher_text,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StreamTransformationFilter(
                aes_cbc,
                new CryptoPP::StringSink(plain_text)
            )
        )
    );
    return plain_text;
}

std::string encrypt(const std::string& input, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key){

    std:: string cipher;

    auto aes = CryptoPP::AES::Encryption(key.data(), key.size());
    auto aes_cbc = CryptoPP::CBC_Mode_ExternalCipher::Encryption(aes, iv.data());

    CryptoPP::StringSource ss(
        input,
        true,
        new CryptoPP::StreamTransformationFilter(
            aes_cbc,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(cipher),
                false // Disable insertion of newlines
            )
        )
    );

    return cipher;
}

std::string hashMasterPassword(const std::string& password) {
    std::string digest;
    CryptoPP::SHA256 hash;
    CryptoPP::StringSource(password, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
    return digest;
}


bool run_check(){

    if (std::filesystem::exists("master_hash.txt")){

    std::string stored_hash;
    std::ifstream inFile("master_hash.txt");
    std::getline(inFile, stored_hash);

    std::string keyLine;
    std::getline(inFile, keyLine);
    std::vector<uint8_t> stored_key;
    std::stringstream ss(keyLine);
    std::string token;

    while (std::getline(ss, token, ',')) {
        stored_key.push_back(static_cast<uint8_t>(std::stoi(token)));
    }

    entryPassword::key = stored_key;

    inFile.close();

    int tries = 0;
    do {
        std::string master_password;
        std::cout << "Enter master password" << "!\n";
        std::getline(std::cin, master_password);
        std::string input_hash = hashMasterPassword(master_password);
        if (input_hash == stored_hash) {
            std::cout << "Master password is correct." << std::endl;
                return true;
        } else {
            std::cout << "Master password is incorrect." << std::endl;
            ++tries;
            }
    } while(tries<3); 
    return false;
    }

    else {
        std::string new_master_password;
        std::cout << "Enter new master password: " << "!\n";
        std::getline(std::cin, new_master_password);

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    
        CryptoPP::byte purpose = 0;
        const CryptoPP::byte* salt = nullptr;
        size_t saltLen = 0;
        unsigned int iterations = 1000;
        double timeInSeconds = 0.0;
        
        entryPassword::key.resize(entryPassword::AES_KEY_SIZE);

        pbkdf.DeriveKey(
            entryPassword::key.data(),
            entryPassword::key.size(),
            purpose,
            reinterpret_cast<const CryptoPP::byte *>(new_master_password.data()),
            new_master_password.size(),
            salt,
            saltLen,
            iterations,
            timeInSeconds
        );

        std::string new_hash = hashMasterPassword(new_master_password);
        std::ofstream outFile("master_hash.txt");
        outFile << new_hash << "\n";

        for (size_t i = 0; i < entryPassword::key.size(); ++i) {
            outFile << static_cast<int>(entryPassword::key[i]);
            if (i < entryPassword::key.size() - 1) {
                outFile << ",";
            }
        }

        outFile.close();

        return true;
    }

}

entryPassword add_password(std::string service, std::string username, std::string password, std::vector<uint8_t>& key){
    
    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::AutoSeededRandomPool rand;
    rand.GenerateBlock(iv.data(), iv.size());

    std::string encrypted_password = encrypt(password, iv, key);
    entryPassword password_obj(service, username, encrypted_password, iv);
    return password_obj;

}

std::string reveal_password(entryPassword stored_pass){
    
    std::string stored_hash;
    std::ifstream inFile("master_hash.txt");
    std::getline(inFile, stored_hash);
    inFile.close();

    return decrypt(stored_pass.get_password(), stored_pass.get_iv(), entryPassword::key);

}

void display_menu() {
    std::cout << "\nPassword Manager CLI\n";
    std::cout << "1. Add Password\n";
    std::cout << "2. View Password\n";
    std::cout << "3. Remove Password\n";
    std::cout << "4. Exit\n";
}

void writeToFile(const std::vector<entryPassword>& entries, const std::string& filename) {
    std::ofstream outFile(filename);
    if (outFile.is_open()) {
        for (const auto& entry : entries) {
            // Write service, username, password, and IV to the file
            outFile << entry.get_service() << "," << entry.get_username() << "," << entry.get_password();
            // Write the IV as a sequence of bytes separated by spaces
            for (uint8_t byte : entry.get_iv()) {
                outFile << "," << static_cast<int>(byte);
            }
            outFile << "\n";
        }
        outFile.close();
    } else {
        std::cerr << "Unable to open file for writing.\n";
    }
}

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

std::vector<entryPassword> readFromFile(const std::string& filename) {
    std::vector<entryPassword> entries;
    if (!fileExists(filename)) {
        std::cout << "File does not exist. Creating a new file when saving.\n";
        return entries; // Return empty vector
    }
    std::ifstream inFile(filename);
    if (inFile.is_open()) {
        std::string line;
        std::istringstream iss(filename);

        for (line; std::getline(iss, line);){
            while (std::getline(inFile, line)) {
                std::stringstream ss(line);
                std::string service, username, password;
                std::vector<uint8_t> ivBytes;

                // Read service
                std::getline(ss, service, ',');
                // Read username
                std::getline(ss, username, ',');
                // Read password
                std::getline(ss, password, ',');

                // Read IV bytes (assuming 16 bytes)
                std::string token;
                for (int i = 0; i < 16 && std::getline(ss, token, ','); ++i) {
                    ivBytes.push_back(static_cast<uint8_t>(std::stoi(token)));
                }

                entries.emplace_back(service, username, password, ivBytes);
            }
    }
        inFile.close();
    } else {
        std::cerr << "Unable to open file for reading.\n";
    }
    return entries;
}

void view_passwords(const std::vector<entryPassword>& entries) {
    if (entries.empty()) {
        std::cout << "No passwords to display.\n";
        return;
    }

    std::cout << "\nStored Passwords:\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        std::string decrypted_password = decrypt(entry.get_password(), entry.get_iv(), entryPassword::key);
        std::cout << "Index: " << i << "\n";
        std::cout << "Service: " << entry.get_service() << "\n";
        std::cout << "Username: " << entry.get_username() << "\n";
        std::cout << "Password: " << decrypted_password << "\n";
        std::cout << "------------------------\n";
    }
}

void remove_password(std::vector<entryPassword>& entries, int index){
    if (index < entries.size()){
        entries.erase(entries.begin()+index);
    } else {
        std::cout << "Invalid index" << "\n";
    }
}









