# CLI Password Manager
CLI based password manager with [AES](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard) encryption implemented using Crypto++.
There is an executable file included in the project which can run on Unix systems.
To change the source code, atleast C++17 and Crypto++ has to be installed. Otherwise, the program is statically linked to the Crypto++ library so it can run without dependancies.

The encryption is executed using the master key and a unique initializing vector (IV). The master key is set during the first run and then stored as a hash. To unlock the vault of passwords, you have to enter the master password, and if the hash of the entered password matches, the vault unlocks. Setting a good master password is essential. 

This IV is "salted", which means that an extra layer of randommness has been used to derive the vector. This means that if we have multiple identical passwords stored, then the encryption string for these passwords are not identical.

# Prerequisits
- **Unix** based system.
# Run
1. **Run the application**:
    ```sh
   git clone <repository-url>
   cd <repository-directory>
   ./program
    ```

# Build from Source
1. **Install dependencies**:
   ```sh
   sudo apt install g++ libcrypto++-dev
   ```
2. **Build the application**:
   ```sh
    g++ -o program main.cpp entryPassword.cpp passwordFunctions.cpp -lcryptopp -static
   ```

# Future Improvements
- Implement [authenticated AES](https://www.cryptopp.com/wiki/Authenticated_Encryption)
- Develop a graphical user interface (GUI)
- Improve function logic, improve efficiency etc.
```
