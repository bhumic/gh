#pragma once

#include "util.h"
#include "pe.h"

// Base class for all of the injection classes
class injector_t
{
public:
    // inject shellcode into a process described with PROCESS_INFO
    void inject_shellcode(const PROCESS_INFO& process_info, const std::vector<BYTE>& shellcode);
};