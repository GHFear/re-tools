# re-tools

*This project was made to make it easier to reverse engineer C code and to make it easier to dump AES keys from the most used AES crypt libraries.* <br>

**Supported AES libs:** <br>
**UE5 Type:** https://github.com/EpicGames/UnrealEngine/blob/5.3/Engine/Source/Runtime/Core/Private/Misc/AES.cpp <br>
**UE4 Type:** https://github.com/EpicGames/UnrealEngine/blob/4.27/Engine/Source/Runtime/Core/Private/Misc/AES.cpp <br>
**cryptoPP type:** https://github.com/weidai11/cryptopp/blob/master/rijndael.cpp <br>
**openssl version < 3.0:** https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c <br>
**matt-wu type:** https://github.com/matt-wu/AES/blob/master/rijndael.c <br>
**libgcrypt/GnuPG type:** https://github.com/Chronic-Dev/libgcrypt/blob/master/cipher/rijndael.c <br>

*Use IDA, Ghidra, Cutter or Binary Ninja and binary search for the first 8 bytes of the Te, Td or rcon arrays and then xref those to find the AES setup functions.* <br>
*Inludes dxgi proxy loading and Minhook as external tools.* <br> <br>
*/GHFear*



