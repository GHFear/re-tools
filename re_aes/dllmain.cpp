#include <Windows.h>
#include "dllmain.h"

/*

This project was made to make it easier to reverse engineer C code and to make it easier to dump AES keys from the most used AES crypt libraries.

UE5 Type: https://github.com/EpicGames/UnrealEngine/blob/5.3/Engine/Source/Runtime/Core/Private/Misc/AES.cpp
UE4 Type: https://github.com/EpicGames/UnrealEngine/blob/4.27/Engine/Source/Runtime/Core/Private/Misc/AES.cpp
cryptoPP type: https://github.com/weidai11/cryptopp/blob/master/rijndael.cpp
openssl version < 3.0: https://github.com/openssl/openssl/blob/OpenSSL_1_1_1-stable/crypto/aes/aes_core.c
matt-wu type: https://github.com/matt-wu/AES/blob/master/rijndael.c
libgcrypt/GnuPG type: https://github.com/Chronic-Dev/libgcrypt/blob/master/cipher/rijndael.c

Use IDA, Ghidra, Cutter or Binary Ninja and binary search for the first 8 bytes of the Te, Td or rcon arrays and thesn xref those to find the AES setup functions.

/GHFear

*/

HMODULE ourModule = 0;

bool hooks()
{
    //This is an example of how to setup the AES hook. This sig works for UE4.27 Game - Session: SkateSim.
    if (!re::hook_create_enable("40 ?? 56 41 ?? 41 ?? 48 ?? ?? ?? 0F ?? ?? ?? 4C", re::rijndaelSetupEncrypt_Hook, &re::rijndaelSetupEncrypt_Orig)) { return false; }
    return true;
}

bool initialize_hooks()
{
    re::create_console();
    re::clear_log();
    if (re::set_exe_base() != true) { return false; }
    re::hook_initialize();
    if (hooks() != true) { return false; }
    return true;
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        re::dxgi_proxy_load_dll(hModule, ourModule);
        if (initialize_hooks() == false) { goto exit; }
        break;
    case DLL_PROCESS_DETACH:
        re::dxgi_proxy_detach();
        break;
    }
exit:
    return TRUE;
}

