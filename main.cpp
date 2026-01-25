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
#include <map>
#include <vector>
#include <cstring>
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Button.H>
#include <FL/fl_ask.H>
#include <filesystem>


class entryPassword {

private:
    std::string service;
    std::string username;
    std::string password;
    std::vector<uint8_t> iv;

public:

    static constexpr size_t AES_KEY_SIZE = 256 / 8; //AES-256
    static inline std::vector<uint8_t> key;

    entryPassword(std::string service, std::string username, std::string password, std::vector<uint8_t> iv){
        this->service = service;
        this->username = username;
        this->password = password;
        this->iv = iv;
    }

    std::string get_service() const {
        return this->service;
    }
    std::string get_username() const {
        return this->username;
    }
    std::string get_password() const {
        return this->password;
    }
    std::vector<uint8_t> get_iv() const {
        return this->iv;
    }

    void set_iv(std::vector<uint8_t> iv) {
        this->iv = iv;
    }

    void set_service(std::string service) {
        this->service = service;
    }

    void set_username(std::string username) {
        this->username = username;
    }

    void set_password(std::string password) {
        this->password = password;
    }
};



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

// Function to hash the master password
std::string hashMasterPassword(const std::string& password) {
    std::string digest;
    CryptoPP::SHA256 hash;
    CryptoPP::StringSource(password, true, new CryptoPP::HashFilter(hash, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
    return digest;
}



//idea is to store encrypted password with their id in the passwords vector.
//its a dynamica array
//Steps: 2 different functions that will be called on clicks, we do remove and add password
// add function needs to take input parameters of new details for the password 
// masterpassword are used to encrypt all stored passwords, for decrypt we generate a key
// with the masterpassword. Each of the "Reveal password" will decrypt on their own. 

// first we need to get a cin to enter masterpassword, if its correct we proceed, else we terminate
// note here that we can run this procedure in tha main function, then if we are correct we call gui

//init 
//std::string hashMasterPassword(const std::string& password)
//std::string encrypt(const std::string& input, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);
//-std::string decrypt(const std::string& cipher_text, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& key);

// if we were to delete the master_hash.txt file after first execution we would bypass this check
// but the hash created with a new password would not be able to encrypt the stored passwords..
// so, it should be safe?

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

    std::string master_password;
    std::cout << "Enter master password" << "!\n";
    std::getline(std::cin, master_password);
    std::string input_hash = hashMasterPassword(master_password);

    if (input_hash == stored_hash) {
    std::cout << "Master password is correct." << std::endl;
        return true;
    // should add tries here
    } else {
        std::cout << "Master password is incorrect." << std::endl;
        return false;
        }
    }
    else {
        std::string new_master_password;
        std::cout << "Enter new master password: " << "!\n";
        std::getline(std::cin, new_master_password);

        // derives the key for encryption and decryption, class variable
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

            // Write the key to the file as well
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

//adds new password with details, unique intial vector, encrypts with master hash
// for now we assume the key is derive in math with the master pass and passed with this function
entryPassword add_password(std::string service, std::string username, std::string password, std::vector<uint8_t>& key){
    
    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::AutoSeededRandomPool rand;
    rand.GenerateBlock(iv.data(), iv.size());

    std::string encrypted_password = encrypt(password, iv, key);
    entryPassword password_obj(service, username, encrypted_password, iv);
    return password_obj;

}

//decrypts using masterkey key
std::string reveal_password(entryPassword stored_pass){
    
    std::string stored_hash;
    std::ifstream inFile("master_hash.txt");
    std::getline(inFile, stored_hash);
    inFile.close();

    return decrypt(stored_pass.get_password(), stored_pass.get_iv(), entryPassword::key);

}

//removes a specific password, no encryption/decryption needed
// i dont think we need this function, since we can just use direct pop/delete or soemthing in gui
//std::void remove_password(vector<entryPassword> item){

//}

void display_menu() {
    std::cout << "\nPassword Manager CLI\n";
    std::cout << "1. Add Password\n";
    std::cout << "2. View Password\n";
    std::cout << "3. Exit\n";
    std::cout << "Enter your choice: ";
}

// Function to write a vector of entryPassword objects to a file
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

// Function to read a vector of entryPassword objects from a file
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

int main() {
    
    std::string filename = "passwords.txt";

    std::vector<entryPassword> entries;

    entries = readFromFile(filename);

    if (entries.empty()) {
            std::cout << "No existing passwords found. Starting with an empty list.\n";
        } else {
            std::cout << "Loaded " << entries.size() << " passwords from file.\n";
        }

    bool auth = run_check();

    if (auth  == true) {

        int choice;
        do {
            //writeToFile(entries, filename);

            display_menu(); // Display menu at the start of each loop iteration

            std::cin >> choice;
            std::cin.ignore(); // Clear the newline character from the input buffer

            switch (choice) {
                case 1: {
                    std::string service_new;
                    std::cout << "Enter service :";
                    std::getline(std::cin, service_new);

                    std::string username_new;
                    std::cout << "Enter username :";
                    std::getline(std::cin, username_new);

                    std::string password_new;
                    std::cout << "Enter password :";
                    std::getline(std::cin, password_new);

                    entryPassword entry = add_password(service_new, username_new, password_new, entryPassword::key);
                    entries.push_back(entry);
                    writeToFile(entries, filename);
                    break; }
                case 2: {
                    view_passwords(entries);
                    break; }
                case 3: {
                    std::cout << "Exiting...\n";
                    break; }
                default:{
                    std::cout << "Invalid choice. Please try again.\n"; 
                    break;
                }
            }
        } while (choice != 3);

    } else {
        return 0;
    }
    return 0;
}


