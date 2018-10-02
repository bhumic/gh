#pragma once

#include <Windows.h>

template <typename T>
T read_memory(LPVOID addr)
{
    return *((T*)addr);
}

template <typename T>
void write_memory(LPVOID addr, T value)
{
    *((T*)addr) = value;
}

template <typename T>
T* read_pointer(LPVOID addr)
{
    return (T*)addr;
}