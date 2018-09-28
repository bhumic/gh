#include <Windows.h>

DWORD WINAPI run_code(LPVOID param)
{
    MessageBoxA(NULL, "Hello from injected DLL!", "DLL injection test", MB_OK);
    return 1;
}

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{

    HANDLE thread = NULL;
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        thread = CreateThread(NULL, 0, &run_code, NULL, 0, NULL);
        CloseHandle(thread);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}