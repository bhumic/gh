#pragma once

#include <vector>
#include <Windows.h>

namespace gh
{
    namespace shellcode
    {
        // x86 shellcode to spawn FatalExit message box which eventually exits the injected process
        std::vector<BYTE> shellcode_fatalexit_32 = { 0x31, 0xd2, 0xb2, 0x30, 0x64, 0x8b, 0x12, 0x8b, 0x52, 0x0c, 0x8b, 0x52,
                                                     0x1c, 0x8b, 0x42, 0x08, 0x8b, 0x72, 0x20, 0x8b, 0x12, 0x80, 0x7e, 0x0c,
                                                     0x33, 0x75, 0xf2, 0x89, 0xc7, 0x03, 0x78, 0x3c, 0x8b, 0x57, 0x78, 0x01,
                                                     0xc2, 0x8b, 0x7a, 0x20, 0x01, 0xc7, 0x31, 0xed, 0x8b, 0x34, 0xaf, 0x01,
                                                     0xc6, 0x45, 0x81, 0x3e, 0x46, 0x61, 0x74, 0x61, 0x75, 0xf2, 0x81, 0x7e,
                                                     0x08, 0x45, 0x78, 0x69, 0x74, 0x75, 0xe9, 0x8b, 0x7a, 0x24, 0x01, 0xc7,
                                                     0x66, 0x8b, 0x2c, 0x6f, 0x8b, 0x7a, 0x1c, 0x01, 0xc7, 0x8b, 0x7c, 0xaf,
                                                     0xfc, 0x01, 0xc7, 0x68, 0x79, 0x74, 0x65, 0x01, 0x68, 0x6b, 0x65, 0x6e,
                                                     0x42, 0x68, 0x20, 0x42, 0x72, 0x6f, 0x89, 0xe1, 0xfe, 0x49, 0x0b, 0x31,
                                                     0xc0, 0x51, 0x50, 0xff, 0xd7 };

        // x86 shellcode to spawn a MessageBoxA without crashing the process being injected
        std::vector<BYTE> shellcode_msgboxa_32 = { 0x31, 0xD2, 0xB2, 0x30, 0x64, 0x8B, 0x12, 0x8B, 0x52, 0x0C, 0x8B, 0x52,
                                                   0x1C, 0x8B, 0x42, 0x08, 0x8B, 0x72, 0x20, 0x8B, 0x12, 0x80, 0x7E, 0x08,
                                                   0x33, 0x75, 0xF2, 0x89, 0xC7, 0x03, 0x78, 0x3C, 0x8B, 0x57, 0x78, 0x01,
                                                   0xC2, 0x8B, 0x7A, 0x20, 0x01, 0xC7, 0x31, 0xED, 0x8B, 0x34, 0xAF, 0x01,
                                                   0xC6, 0x45, 0x81, 0x3E, 0x4D, 0x65, 0x73, 0x73, 0x75, 0xF2, 0x81, 0x7E,
                                                   0x07, 0x42, 0x6F, 0x78, 0x41, 0x75, 0xE9, 0x8B, 0x7A, 0x24, 0x01, 0xC7,
                                                   0x66, 0x8B, 0x2C, 0x6F, 0x8B, 0x7A, 0x1C, 0x01, 0xC7, 0x8B, 0x7C, 0xAF,
                                                   0xFC, 0x01, 0xC7, 0x68, 0x79, 0x74, 0x65, 0x01, 0x68, 0x6B, 0x65, 0x6E,
                                                   0x42, 0x68, 0x20, 0x42, 0x72, 0x6F, 0x89, 0xE1, 0xFE, 0x49, 0x0B, 0x6A,
                                                   0x00, 0x6A, 0x00, 0x51, 0x6A, 0x00, 0xFF, 0xD7, 0x83, 0xC4, 0x0C, 0xC3 };
    }
}