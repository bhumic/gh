#pragma once


/*char buffer[256];
DWORD oldProtect = 0;
DWORD numRead = 0;
BOOL status;
status = VirtualProtectEx((HANDLE)handle.get(), (LPVOID)0x1110000, 256, PAGE_EXECUTE_READWRITE, &oldProtect);
print_error(GetLastError());
status = ReadProcessMemory(handle.get(), (LPVOID)0x1110000, buffer, 256, &numRead);
print_error(GetLastError());
status = VirtualProtectEx(handle.get(), (LPVOID)0x1110000, 256, oldProtect, NULL);
print_error(GetLastError());
*/