#define WIN32_LEAN_AND_MEAN 
#include <windows.h>

//For getting IP From File bgamert5_ip.txt
#include <iostream>
#include <fstream>
#include <string>

//For getting IP From Adatper
#include <iphlpapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "iphlpapi.lib")

unsigned long ip_str_to_network_order(const char* ip_str) {
    unsigned int b1, b2, b3, b4;
    if (sscanf(ip_str, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4) {
        return 0; // Invalid IP format
    }

    return (b1) | (b2 << 8) | (b3 << 16) | b4 << 24;
}


unsigned long getIPFromAdapter() {
    IP_ADAPTER_INFO adapterInfo[16]; // enough for most systems
    DWORD bufLen = sizeof(adapterInfo);

    DWORD status = GetAdaptersInfo(adapterInfo, &bufLen);
    if (status != ERROR_SUCCESS) {
        std::cerr << "GetAdaptersInfo failed." << std::endl;
        return NULL;
    }

    PIP_ADAPTER_INFO adapter = adapterInfo;
    while (adapter) {
        std::string ip = adapter->IpAddressList.IpAddress.String;
        if (ip.rfind("192", 0) == 0) {
            //std::cout << "Found IP: " << ip << std::endl;
            return ip_str_to_network_order(ip.c_str());
        }
        adapter = adapter->Next;
    }

    std::cout << "No IP starting with 192 found." << std::endl;
    return NULL;
}


//Read from file

std::string ReadIPFromFile(const char* filePath) {
    std::ifstream file(filePath);
    std::string ip;
    if (file.is_open()) 
    {
        std::getline(file, ip);
        file.close();
    }
    else 
    {
        return std::string();
    }
    return ip;
}


unsigned long getIP() 
{
    std::string ip = ReadIPFromFile("bgamert5_ip.txt");
    if (!ip.empty())
    {
        return ip_str_to_network_order(ip.c_str());
    }
    else 
    {
        return getIPFromAdapter();
    }
}

//Patch function
typedef struct hostent {
    char* h_name;
    char** h_aliases;
    short h_addrtype;
    short h_length;
    char** h_addr_list;
} hostent;

typedef hostent* (__stdcall* GetHostByNameFn)(const char*);

GetHostByNameFn originalGetHostByName = nullptr;

hostent* __stdcall MyGetHostByName(const char* name) {
    char localHostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(localHostname);
    if (GetComputerNameA(localHostname, &size)) {
        if (_stricmp(name, localHostname) == 0 || _stricmp(name, "127.0.0.1") == 0) {
            static struct hostent h;

            //MAGIC
            #undef s_addr

            static struct in_addr {
                unsigned long s_addr;
            } addr;
            
            
            static char* addr_list[2];
            static char* aliases[1] = { nullptr };

            
            //addr.s_addr = (17 << 24) | (69 << 16) | (168 << 8) | 192;
            addr.s_addr = getIP();

            #define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
            //END OF MAGIC
            h.h_name = localHostname;
            h.h_aliases = aliases;
            h.h_addrtype = 2; // AF_INET
            h.h_length = sizeof(unsigned long);
            addr_list[0] = (char*)&addr;
            addr_list[1] = nullptr;
            h.h_addr_list = addr_list;

            return &h;
        }
    }

    return originalGetHostByName ? originalGetHostByName(name) : nullptr;
}

void PatchIAT() {
    DWORD* iatEntry = (DWORD*)0x009a3470;
    DWORD oldProtect;

    originalGetHostByName = *(GetHostByNameFn*)iatEntry;
    if (VirtualProtect(iatEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *iatEntry = (DWORD)&MyGetHostByName;
        VirtualProtect(iatEntry, sizeof(DWORD), oldProtect, &oldProtect);
    }
}

void Patch(int game) {
    if (game == 1) {
        PatchIAT();
    }
}

extern "C" __declspec(dllexport) int Patchbgt5external(int game) {
    Patch(game);
    return 1;
}
