#include "entryPassword.h"
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
        display_menu();
        int choice;
        int index;
        std::string input;

        do {
            std::cout << "Enter your choice: ";
            std::cin >> input;
            std::cin.ignore();
            try {
                choice = std::stoi(input);
                        
            switch (choice) {
                case 1: {
                    std::string service_new;
                    std::cout << "Service :";
                    std::getline(std::cin, service_new);

                    std::string username_new;
                    std::cout << "Username/email :";
                    std::getline(std::cin, username_new);

                    std::string password_new;
                    std::cout << "Password :";
                    std::getline(std::cin, password_new);

                    entryPassword entry = add_password(service_new, username_new, password_new, entryPassword::key);
                    entries.push_back(entry);
                    writeToFile(entries, filename);

                    std::cout << "Password stored!" << "\n";

                    break; }
                case 2: {
                    view_passwords(entries);
                    break; }
                case 3: {
                    std::string input_index;
                    std::cout << "Index to remove password \n";
                    std::getline(std::cin, input_index);

                    try {
                        index = std::stoi(input_index);
                    }
                    catch (const std::invalid_argument& e) {
                    std::cerr << "Digits only allowed. Invalid argument: " << e.what() << std::endl;
                    }

                    remove_password(entries, index);
                    writeToFile(entries, filename);

                    break; }
                case 4: {
                    std::cout << "Exiting...\n";
                    break; }
                default:{
                    std::cout << "Invalid choice. Please try again.\n"; 
                    break;
                }
            }
        } 
        catch (const std::invalid_argument& e) {
                std::cerr << "Digits only allowed. Invalid argument: " << e.what() << std::endl;
            }

        } while (choice !=4);

    } else {
        return 0;
    }
    return 0;
}