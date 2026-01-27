# Simple Password Manager
CLI based password manager with [AES](https://www.cryptopp.com/wiki/Advanced_Encryption_Standard) encryption implemented using Crypto++.
There is an executable file included in the project which can run on Unix systems.
To change the source code, atleast C++17 and Crypto++ has to be installed. Otherwise, the program is statically linked to the Crypto++ library so it can run anyway.

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
