// Illusory Software RE (Reverse Engineering) Tools 0.1.0.0
// RE::LLUSORY
#pragma once
#include <vector>
#include <intrin.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <cassert>
#include <io.h>
#include <stdio.h>
#include <filesystem>
#include <algorithm>
#include <wchar.h> 
#include "../Minhook/MinHook.h"
#include "../Proxy/proxy.h"

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

#define RELIB_EXPORTS

#ifdef RELIB_EXPORTS
#define RELIB_API __declspec(dllexport)
#else
#define RELIB_API __declspec(dllimport)
#endif

namespace re
{

    // Exe base (we can also set this manually on init if this fails)
    extern char* exe_base;

    // Allocate a console
    RELIB_API bool create_console();

    // Proxy attach and load your dll automatically (dxgi.dll)
    RELIB_API bool dxgi_proxy_load_dll(HMODULE& hModule, HMODULE& ourModule);

    // Proxy detach (dxgi.dll)
    RELIB_API bool dxgi_proxy_detach();

    // Set exe base.
    RELIB_API bool set_exe_base();

    // Get exe base.
    RELIB_API char* get_exe_base();

    // Scan for offset using IDA type signature.
    RELIB_API uintptr_t get_offset(const char* ida_sig);

    // Function to search for an 8-bit character string in process memory and find all occurrences of the same string.
    RELIB_API std::vector<DWORD_PTR> find_8bit_c_strings(const char* target_string);

    // Function to search for an 16-bit character wide string in process memory and find all occurrences of the same string.
    RELIB_API std::vector<DWORD_PTR>find_16bit_c_strings(const wchar_t* target_string);

    // Get the actual memoryaddress inside the host process from an offset.
    RELIB_API LPVOID get_address_from_offset(uintptr_t offset);

    // Get pointer to value from it's offset. (then we need to typecast the return value to use it)
    RELIB_API void* get_data(long long address);

    // Return a void** to the vtable. (this is where you can can get the methods)
      // Input argument is the functions this* (the first function argument).
    RELIB_API void** get_vtable(void* this_ptr);

    // Get VTable information. 
    // Use this version when VTable delimiter is nullptr. (Confirm with IDA, Binary Ninja or Ghidra)
    // The Input argument is the vtable reference that we get from Get_VTable();
    RELIB_API auto get_vtable_info_standard(void** vtable);

    // Get IDA Function Name. Input argument is the function pointer to that address.
    RELIB_API std::string get_ida_function_name(void* function_pointer);

    // Get stack + value
    RELIB_API int Get_RSP(int64_t offset); // Return value register.

    // Get register. (code for this is in re_asm_tools.asm)
    // RXX (64-Bit Wide) (Used for Integers and Pointers)
    extern "C" int Get_RAX(); // Return value register.
    extern "C" int Get_RBX();
    extern "C" int Get_RCX(); // First function argument register.
    extern "C" int Get_RDX(); // Second function argument register.
    extern "C" int Get_R8();  // Third function argument register.
    extern "C" int Get_R9();  // Fourth function argument register.
    extern "C" int Get_R10();
    extern "C" int Get_R11();
    extern "C" int Get_R12();
    extern "C" int Get_R13();
    extern "C" int Get_R14();
    extern "C" int Get_R15();

    // XMM (128-bit Wide) (We still move single precision float so far)
    extern "C" int Get_XMM0();
    extern "C" int Get_XMM1();
    extern "C" int Get_XMM2();
    extern "C" int Get_XMM3();
    extern "C" int Get_XMM4();
    extern "C" int Get_XMM5();
    extern "C" int Get_XMM6();
    extern "C" int Get_XMM7();
    extern "C" int Get_XMM8();
    extern "C" int Get_XMM9();
    extern "C" int Get_XMM10();
    extern "C" int Get_XMM11();
    extern "C" int Get_XMM12();
    extern "C" int Get_XMM13();
    extern "C" int Get_XMM14();
    extern "C" int Get_XMM15();

    // YMM (256-bit Wide) (We still move single precision float so far)
    extern "C" int Get_YMM0();
    extern "C" int Get_YMM1();
    extern "C" int Get_YMM2();
    extern "C" int Get_YMM3();
    extern "C" int Get_YMM4();
    extern "C" int Get_YMM5();
    extern "C" int Get_YMM6();
    extern "C" int Get_YMM7();
    extern "C" int Get_YMM8();
    extern "C" int Get_YMM9();
    extern "C" int Get_YMM10();
    extern "C" int Get_YMM11();
    extern "C" int Get_YMM12();
    extern "C" int Get_YMM13();
    extern "C" int Get_YMM14();
    extern "C" int Get_YMM15();

    // ZMM (512-bit Wide) (We still move single precision float so far)
    extern "C" int Get_ZMM0();
    extern "C" int Get_ZMM1();
    extern "C" int Get_ZMM2();
    extern "C" int Get_ZMM3();
    extern "C" int Get_ZMM4();
    extern "C" int Get_ZMM5();
    extern "C" int Get_ZMM6();
    extern "C" int Get_ZMM7();
    extern "C" int Get_ZMM8();
    extern "C" int Get_ZMM9();
    extern "C" int Get_ZMM10();
    extern "C" int Get_ZMM11();
    extern "C" int Get_ZMM12();
    extern "C" int Get_ZMM13();
    extern "C" int Get_ZMM14();
    extern "C" int Get_ZMM15();
    extern "C" int Get_ZMM16();
    extern "C" int Get_ZMM17();
    extern "C" int Get_ZMM18();
    extern "C" int Get_ZMM19();
    extern "C" int Get_ZMM20();
    extern "C" int Get_ZMM21();
    extern "C" int Get_ZMM22();
    extern "C" int Get_ZMM23();
    extern "C" int Get_ZMM24();
    extern "C" int Get_ZMM25();
    extern "C" int Get_ZMM26();
    extern "C" int Get_ZMM27();
    extern "C" int Get_ZMM28();
    extern "C" int Get_ZMM29();
    extern "C" int Get_ZMM30();
    extern "C" int Get_ZMM31();

    // Function to get the file path of the process that loaded the DLL
    RELIB_API std::string Get_Process_Path();

    // Function to get the wide file path of the process that loaded the DLL
    RELIB_API std::wstring Get_Process_Path_Wide();

    // Function to get the directory path of the process that loaded the DLL
    RELIB_API std::string Get_Exe_Directory();

    // Function to get the wide directory path of the process that loaded the DLL
    RELIB_API std::wstring Get_Exe_Directory_Wide();

    // Logging string to file
    RELIB_API bool relog(const char* format, ...);

    // Logging wide string to file
    RELIB_API bool rewlog(const wchar_t* format, ...);

    // Clear log
    RELIB_API bool clear_log();

    // Log an eas key from the AES Setup. For this we need the key pointer and the key length.
    RELIB_API void log_aes_key(const uint8_t* key, const uint32_t key_len_bits);

    // DoOnce for AES key logging.
    extern bool LogAESKeyOnce;

    // matt-wu
    typedef int32_t(*aes_encrypt_Ptr)(int mode, uint8_t* data, int len, uint8_t* key);
    extern aes_encrypt_Ptr aes_encrypt_Orig;
    int32_t __fastcall aes_encrypt_Hook(int mode, uint8_t* data, int len, uint8_t* key);

    // GNU gcrypt
    typedef int32_t(*do_setkey_Ptr)(void* ctx, const byte* key, const unsigned keylen);
    extern do_setkey_Ptr do_setkey_Orig;
    int32_t __fastcall do_setkey_Hook(void* ctx, const byte* key, const unsigned keylen);


    // OpenSSL < 3.0
    typedef int32_t(*AES_set_encrypt_key_Ptr)(const unsigned char* userKey, const int bits, void* key);
    extern AES_set_encrypt_key_Ptr AES_set_encrypt_key_Orig;
    int32_t __fastcall AES_set_encrypt_key_Hook(const unsigned char* userKey, const int bits, void* key);


    // CryptoPP
    typedef void(*UncheckedSetKey_Ptr)(const byte* userKey, unsigned int keyLen, void* NameValuePairs);
    extern UncheckedSetKey_Ptr UncheckedSetKey_Orig;
    void __fastcall UncheckedSetKey_Hook(const byte* userKey, unsigned int keyLen, void* NameValuePairs);


    // Unreal Engine 4.0 -> 5.1
    typedef int32_t(*rijndaelSetupEncrypt_Ptr)(uint32_t* rk, const uint8_t* key, int32_t keybits);
    extern rijndaelSetupEncrypt_Ptr rijndaelSetupEncrypt_Orig;
    int32_t __fastcall rijndaelSetupEncrypt_Hook(uint32_t* rk, const uint8_t* key, int32_t keybits);


    // Unreal Engine 5.2 and higher.
    typedef void(*AesEncryptExpand_Ptr)(void* EncryptKey, const uint8_t* Key);
    extern AesEncryptExpand_Ptr AesEncryptExpand_Orig;
    void __fastcall AesEncryptExpand_Hook(void* EncryptKey, const uint8_t* Key);
    
    // Initialize minhook.
    RELIB_API bool hook_initialize();

    // Create a function hook and enable that hook with minhook.
    RELIB_API bool hook_create_enable(const char* ida_sig, LPVOID hook_function, void* original_function);

    // Disable a minhook function.
    RELIB_API bool hook_disable(const char* ida_sig);

}

