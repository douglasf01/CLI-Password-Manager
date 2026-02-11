# CLI Password Manager
CLI based password manager with [AES](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard) encryption implemented using Crypto++.
There is an executable file included in the project which can run on Unix systems.
To change the source code, atleast C++17 and Crypto++ has to be installed. Otherwise, the program is statically linked to the Crypto++ library so it can run without dependancies.

![Screenshot for features.](screenshot.png)

The encryption is executed using the master key and a unique initializing vector (IV). Using an IV, implies that identical passwords does not have the same encryption key. This IV is "salted", which means an extra layer of randomness has been used to derive it.

The master key is set during the first run and then stored as a hash. To unlock the vault of passwords, you have to enter the master password, and if the hash of the entered password matches, the vault unlocks. Setting a good master password is essential. 


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

Below, I am using g++ as compiler.

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
- Improve function logic, efficiency
- More functionality, such as editing current password entries


# Misc

Thanks to Tsvetomir Dimitrov [introduction](https://petanode.com/posts/brief-introduction-to-cryptopp/) on the Crypto++ library.
