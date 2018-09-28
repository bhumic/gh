#include <Windows.h>

DWORD WINAPI run_code(LPVOID param)
{
    MessageBoxA(NULL, "Hello from injected DLL!", "DLL injection test", MB_OK);
    return 1;
}

BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        HANDLE thread = CreateThread(NULL, 0, &run_code, NULL, 0, NULL);
        CloseHandle(thread);
        //FreeLibraryAndExitThread(hDll, TRUE);
        break;
    }
    return TRUE;
}