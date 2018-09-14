#include <Windows.h>

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Hello from injected DLL!", "DLL injection test", MB_OK);
        break;
    }

    return TRUE;
}