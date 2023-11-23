// Illusory Software RE (Reverse Engineering) Tools Version 0.1.0.0
// RE::LLUSORY
#pragma once
#include "re_tools.h"

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

namespace re 
{
    

    // Exe base (we can also set this manually on init if this fails)
    char* exe_base = (char*)GetModuleHandleA(NULL);

    RELIB_API bool create_console()
    {
        if (!AllocConsole()) { return false; }
        return true;
    }

    // Proxy attach and load your dll automatically (dxgi.dll)
    RELIB_API bool dxgi_proxy_load_dll(HMODULE& hModule, HMODULE& ourModule)
    {
        ourModule = hModule;
        if (!Proxy_Attach()) { return false; }
        return true;
    }

    // Proxy detach (dxgi.dll)
    RELIB_API bool dxgi_proxy_detach()
    {
        try { Proxy_Detach(); }
        catch (const std::exception&) { return false; }
        return true;
    }

    // Set exe base.
    RELIB_API bool set_exe_base()
    {
        exe_base = (char*)GetModuleHandleA(NULL);
        if (!exe_base) { return false; }
        return true;
    }

    // Get exe base.
    RELIB_API char* get_exe_base()
    {
        return exe_base;
    }

    // Scan for offset using IDA type signature.
    RELIB_API uintptr_t get_offset(const char* ida_sig)
    {

        auto lambda_find = [](const char* module, const char* pattern)
            {
                uintptr_t module_adress = 0;
                module_adress = *(uintptr_t*)(__readgsqword(0x60) + 0x10);

                auto lambda_pattern_to_byte = [](const char* pattern)
                    {
                        auto bytes = std::vector<int>{};
                        const auto start = const_cast<char*>(pattern);
                        const auto end = const_cast<char*>(pattern) + strlen(pattern);

                        for (auto current = start; current < end; ++current)
                        {
                            if (*current == '?')
                            {
                                ++current;
                                if (*current == '?')
                                    ++current;
                                bytes.push_back(-1);
                            }
                            else { bytes.push_back(strtoul(current, &current, 16)); }
                        }
                        return bytes;
                    };

                const auto dos_header = (IMAGE_DOS_HEADER*)module_adress;
                const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uint8_t*)module_adress + dos_header->e_lfanew);

                const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
                auto pattern_bytes = lambda_pattern_to_byte(pattern);
                const auto scan_bytes = reinterpret_cast<std::uint8_t*>(module_adress);

                const auto pattern_size = pattern_bytes.size();
                const auto pattern_data = pattern_bytes.data();

                for (auto i = 0ul; i < size_of_image - pattern_size; ++i)
                {
                    bool found = true;
                    for (auto j = 0ul; j < pattern_size; ++j)
                    {
                        if (scan_bytes[i + j] != pattern_data[j] && pattern_data[j] != -1)
                        {
                            found = false;
                            break;
                        }
                    }
                    if (found) { return reinterpret_cast<uintptr_t>(&scan_bytes[i]); }
                }
                return (uintptr_t)NULL;
            };


        auto offset = lambda_find(nullptr, ida_sig);
        if (offset == 0) { return -1; }

        return offset - (uintptr_t)GetModuleHandleW(nullptr);
    }

#ifdef _WIN32
    // Define stristr for Windows
    char* stristr(const char* str1, const char* str2)
    {
        char* p1 = nullptr;
        char* p2 = nullptr;
        char* p3 = nullptr;

        if (!*str2) return (char*)str1;

        while (*str1)
        {
            p1 = (char*)str1;
            p2 = (char*)str2;

            // compare the lower-case characters
            while (*p1 && *p2 && tolower(*p1) == tolower(*p2))
            {
                p1++;
                p2++;
            }

            // check if the substring is found
            if (!*p2)
                return (char*)str1;

            // move to the next character in the main string
            str1++;
        }
        return nullptr;
    }
#endif

    // Function to search for an 8-bit character string in process memory and find all occurrences of the same string.
    RELIB_API std::vector<DWORD_PTR> find_8bit_c_strings(const char* target_string)
    {
        std::vector<DWORD_PTR> references;

        const char* moduleBase = reinterpret_cast<const char*>(GetModuleHandleA(nullptr));

        uintptr_t module_adress = 0;
        module_adress = *(uintptr_t*)(__readgsqword(0x60) + 0x10);
        const auto dos_header = (IMAGE_DOS_HEADER*)module_adress;
        const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uint8_t*)module_adress + dos_header->e_lfanew);

        const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;

        // Iterate through the process memory
        const char* baseAddress = moduleBase;
        const char* endAddress = baseAddress + size_of_image;  // Adjust the range as needed

        while (baseAddress < endAddress) {
            // Search for the target string in the memory (case-insensitive)
            const char* result = stristr(baseAddress, target_string);

            while (result != nullptr) {

                // Calculate the offset of the found string in the memory
                DWORD_PTR offset = static_cast<DWORD_PTR>(reinterpret_cast<uintptr_t>(result) - reinterpret_cast<uintptr_t>(moduleBase));

                // Store the cross-reference address
                references.push_back(offset);

                // Move to the next occurrence of the string in the memory
                result = stristr(result + 1, target_string);
            }

            // Move to the next memory region
            baseAddress += strlen(baseAddress) + 1;  // Move to the next null-terminated string
        }

        return references;
    }

    // Case-insensitive comparison of two wide characters
    bool CaseInsensitiveWideCharCompare(wchar_t ch1, wchar_t ch2) {
        return towlower(ch1) == towlower(ch2);
    }

    // Case-insensitive search for wide strings
    const wchar_t* CaseInsensitiveWideStrStr(const wchar_t* str, const wchar_t* target) {
        while (*str != L'\0') {
            const wchar_t* p1 = str;
            const wchar_t* p2 = target;

            while (*p1 != L'\0' && *p2 != L'\0' && CaseInsensitiveWideCharCompare(*p1, *p2)) {
                p1++;
                p2++;
            }

            if (*p2 == L'\0') {
                return str;  // Match found
            }

            str++;
        }

        return nullptr;  // No match found
    }

    RELIB_API std::vector<DWORD_PTR>find_16bit_c_strings(const wchar_t* target_string)
    {
        std::vector<DWORD_PTR> references;

        const char* moduleBase = reinterpret_cast<const char*>(GetModuleHandleA(nullptr));

        uintptr_t module_adress = 0;
        module_adress = *(uintptr_t*)(__readgsqword(0x60) + 0x10);
        const auto dos_header = (IMAGE_DOS_HEADER*)module_adress;
        const auto nt_headers = (IMAGE_NT_HEADERS*)((std::uint8_t*)module_adress + dos_header->e_lfanew);

        const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;

        // Iterate through the process memory
        const char* baseAddress = moduleBase;
        const char* endAddress = baseAddress + size_of_image;  // Adjust the range as needed

        while (baseAddress < endAddress) {
            // Search for the target string in the memory (case-insensitive)
            const wchar_t* result = CaseInsensitiveWideStrStr(reinterpret_cast<const wchar_t*>(baseAddress), target_string);

            while (result != nullptr) {
                // Calculate the offset of the found string in the memory
                DWORD_PTR offset = static_cast<DWORD_PTR>(reinterpret_cast<uintptr_t>(result) - reinterpret_cast<uintptr_t>(moduleBase));

                // Store the cross-reference address
                references.push_back(offset);

                // Move to the next occurrence of the string in the memory
                result = CaseInsensitiveWideStrStr(result + 1, target_string);
            }

            // Move to the next memory region
            baseAddress += (wcslen(reinterpret_cast<const wchar_t*>(baseAddress)) + 1) * sizeof(wchar_t);  // Move to the next null-terminated wide string
        }

        return references;
    }

    // Get the actual memoryaddress inside the host process from an offset.
    RELIB_API LPVOID get_address_from_offset(uintptr_t offset)
    {
        return reinterpret_cast<LPVOID>(get_exe_base() + offset);
    }

    // Get pointer to value from it's offset. (then we need to typecast the return value to use it)
    RELIB_API void* get_data(long long address)
    {
        uintptr_t data_addr = reinterpret_cast<uintptr_t>((void*)address);
        void* data_ptr = reinterpret_cast<void*>(data_addr);
        return data_ptr;
    }

    // Return a void** to the vtable. (this is where you can can get the methods)
      // Input argument is the functions this* (the first function argument).
    RELIB_API void** get_vtable(void* this_ptr)
    {
        void** vtable = *(void***)(this_ptr);
        return vtable;
    }

    // Get VTable information. 
    // Use this version when VTable delimiter is nullptr. (Confirm with IDA, Binary Ninja or Ghidra)
    // The Input argument is the vtable reference that we get from Get_VTable();
    RELIB_API auto get_vtable_info_standard(void** vtable)
    {
        struct RETURN { uint32_t function_count;  std::vector<void*> class_functions; };
        std::vector<void*> class_functions = {};
        uint32_t function_count = 0;
        while (vtable[function_count] != nullptr)
        {
            class_functions.push_back(vtable[function_count]);
            function_count++;
        }
        return RETURN{ function_count , class_functions };
    };

    // Get IDA Function Name. Input argument is the function pointer to that address.
    RELIB_API std::string get_ida_function_name(void* function_pointer)
    {
        // Convert the hexadecimal string to an integer
        unsigned long long intValue = reinterpret_cast<unsigned long long>(function_pointer);

        // Convert the integer back to a hexadecimal string without leading zeros
        std::stringstream ss;
        ss << std::hex << intValue;

        // Add sub_ to start of function address
        std::string ida_sub_name = "sub_" + ss.str();

        return ida_sub_name;
    }

    // Function to get the file path of the process that loaded the DLL
    RELIB_API std::string Get_Process_Path() {
        wchar_t buffer[MAX_PATH];
        DWORD result = GetModuleFileName(nullptr, buffer, MAX_PATH);
        if (result == 0) {
            // Handle error, e.g., call GetLastError() for details
            return "";
        }
        std::filesystem::path filePath = std::wstring(buffer);
        return filePath.string();
    }

    // Function to get the wide file path of the process that loaded the DLL
    RELIB_API std::wstring Get_Process_Path_Wide() {
        wchar_t buffer[MAX_PATH];
        DWORD result = GetModuleFileName(nullptr, buffer, MAX_PATH);
        if (result == 0) {
            // Handle error, e.g., call GetLastError() for details
            return L"";
        }
        std::filesystem::path filePath = std::wstring(buffer);
        return filePath.wstring();
    }

    // Function to get the directory path of the process that loaded the DLL
    RELIB_API std::string Get_Exe_Directory()
    {
        std::string process_path = Get_Process_Path();
        std::filesystem::path filePath = process_path;
        std::filesystem::path directoryPath = filePath.parent_path();
        return directoryPath.string();
    }

    // Function to get the wide directory path of the process that loaded the DLL
    RELIB_API std::wstring Get_Exe_Directory_Wide()
    {
        std::wstring process_path = Get_Process_Path_Wide();
        std::filesystem::path filePath = process_path;
        std::filesystem::path directoryPath = filePath.parent_path();
        return directoryPath.wstring();
    }

    // Logging string to file
    RELIB_API bool relog(const char* format, ...)
    {
        std::string exe_dir = Get_Exe_Directory().c_str();
        exe_dir = exe_dir + "\\rellusory.log";

        FILE* file = nullptr;
        if (_access(exe_dir.c_str(), 0) == 0) { file = fopen(exe_dir.c_str(), "a"); }
        else { file = fopen(exe_dir.c_str(), "w"); }

        if (file == NULL) 
        {
            perror("Error opening file");
            return false;
        }

        va_list args;
        va_start(args, format);
        vfprintf(file, format, args);
        va_end(args);
        fclose(file);
        return true;
    }

    // Logging wide string to file
    RELIB_API bool rewlog(const wchar_t* format, ...)
    {
        std::wstring exe_dir = Get_Exe_Directory_Wide().c_str();
        exe_dir = exe_dir + L"\\rellusory.log";

        FILE* file = nullptr;
        if (_waccess(exe_dir.c_str(), 0) == 0) { file = _wfopen(exe_dir.c_str(), L"a"); }
        else { file = _wfopen(exe_dir.c_str(), L"w"); }

        if (file == NULL) 
        {
            perror("Error opening file");
            return false;
        }

        va_list args;
        va_start(args, format);
        vfwprintf(file, format, args);
        va_end(args);
        fclose(file);
        return true;
    }

    // Clear log
    RELIB_API bool clear_log()
    {
        std::wstring exe_dir = Get_Exe_Directory_Wide().c_str();
        exe_dir = exe_dir + L"\\rellusory.log";

        FILE* file = nullptr;
        if (_waccess(exe_dir.c_str(), 0) == 0) { file = _wfopen(exe_dir.c_str(), L"w"); }
        else { return true; }

        if (file == NULL) 
        {
            perror("Error opening file");
            return false;
        }

        fprintf(file, "RE::LLUSORY\n\n");
        fclose(file);
        return true;
    }

    // Log an eas key from the AES Setup. For this we need the key pointer and the key length.
    RELIB_API void log_aes_key(const uint8_t* key, const uint32_t key_len_bits)
    {
        auto user_key = reinterpret_cast<unsigned char*>((unsigned char*)key + 0);

        relog("AES KEY: ");
        for (size_t i = 0; i < (key_len_bits / 8); i++)
        {
            user_key = reinterpret_cast<unsigned char*>((unsigned char*)key + i);
            relog("%02X", *user_key);
        }
        relog("\n");

        return;
    }

    bool LogAESKeyOnce = true;

    // matt-wu
    aes_encrypt_Ptr aes_encrypt_Orig = nullptr;
    int32_t __fastcall aes_encrypt_Hook(int mode, uint8_t* data, int len, uint8_t* key)
    {
        if (LogAESKeyOnce == true && mode >= 0 && mode <= 2)
        {
            int g_aes_key_bits[] = { 128, 192, 256, };
            log_aes_key(key, g_aes_key_bits[mode]);
            LogAESKeyOnce = false;
        }
        return aes_encrypt_Orig(mode, data, len, key);
    }

    // GNU gcrypt
    do_setkey_Ptr do_setkey_Orig = nullptr;
    int32_t __fastcall do_setkey_Hook(void* ctx, const byte* key, const unsigned keylen)
    {
        if (LogAESKeyOnce == true)
        {
            log_aes_key(key, keylen);
            LogAESKeyOnce = false;
        }
        return do_setkey_Orig(ctx, key, keylen);
    }

    // OpenSSL < 3.0
    AES_set_encrypt_key_Ptr AES_set_encrypt_key_Orig = nullptr;
    int32_t __fastcall AES_set_encrypt_key_Hook(const unsigned char* userKey, const int bits, void* key)
    {
        if (LogAESKeyOnce == true)
        {
            log_aes_key(userKey, bits);
            LogAESKeyOnce = false;
        }
        return AES_set_encrypt_key_Orig(userKey, bits, key);
    }

    // CryptoPP
    UncheckedSetKey_Ptr UncheckedSetKey_Orig = nullptr;
    void __fastcall UncheckedSetKey_Hook(const byte* userKey, unsigned int keyLen, void* NameValuePairs)
    {
        if (LogAESKeyOnce == true)
        {
            log_aes_key(userKey, keyLen);
            LogAESKeyOnce = false;
        }
        return UncheckedSetKey_Orig(userKey, keyLen, NameValuePairs);
    }

    // Unreal Engine 4.0 -> 5.1
    rijndaelSetupEncrypt_Ptr rijndaelSetupEncrypt_Orig = nullptr;
    int32_t __fastcall rijndaelSetupEncrypt_Hook(uint32_t* rk, const uint8_t* key, int32_t keybits)
    {
        if (LogAESKeyOnce == true)
        {
            log_aes_key(key, keybits);
            LogAESKeyOnce = false;
        }
        return rijndaelSetupEncrypt_Orig(rk, key, keybits);
    }

    // Unreal Engine 5.2 and higher.
    AesEncryptExpand_Ptr AesEncryptExpand_Orig = nullptr;
    void __fastcall AesEncryptExpand_Hook(void* EncryptKey, const uint8_t* Key)
    {
        if (LogAESKeyOnce == true)
        {
            log_aes_key(Key, 256);
            LogAESKeyOnce = false;
        }
        return AesEncryptExpand_Orig(EncryptKey, Key);
    }

    // Initialize minhook.
    RELIB_API bool hook_initialize()
    {
        if (MH_Initialize() != MH_OK) { return false; }
        return true;
    }

    // Create a function hook and enable that hook with minhook.
    RELIB_API bool hook_create_enable(const char* ida_sig, LPVOID hook_function, void* original_function)
    {
        auto function_address = get_address_from_offset(get_offset(ida_sig));
        if (MH_CreateHook(function_address, hook_function, (LPVOID*)original_function) != MH_OK) { return false; }
        if (MH_EnableHook(function_address) != MH_OK) { return false; }
        return true;
    }

    // Disable a minhook function.
    RELIB_API bool hook_disable(const char* ida_sig)
    {
        auto function_address = get_address_from_offset(get_offset(ida_sig));
        if (MH_DisableHook(function_address) != MH_OK) { return false; }
        return true;
    }
}

