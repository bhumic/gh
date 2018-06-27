#include "pe.h"

pe_parser_t* create_pe_parser(PROCESS_INFO& process_info)
{
    if (process_info.is64bit)
        return new pe64_parser_t(process_info);
    return new pe32_parser_t(process_info);
}


void pe_parser_t::obtain_handle()
{
    this->handle = get_process_handle(this->process_info.pid);
}

void pe_parser_t::read_dos_header()
{
    boost::uint32_t old_protection = protect_memory<IMAGE_DOS_HEADER>(handle.get(), (LPVOID)process_info.base, PAGE_EXECUTE_READWRITE);
    dos_header = *read_memory<IMAGE_DOS_HEADER>(handle.get(), (LPVOID)process_info.base);
    protect_memory<IMAGE_DOS_HEADER>(handle.get(), (LPVOID)process_info.base, old_protection);
}

void pe32_parser_t::read_nt_header()
{
    boost::uint32_t old_protection = protect_memory<IMAGE_NT_HEADERS32>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), PAGE_EXECUTE_READWRITE);
    nt_header = *read_memory<IMAGE_NT_HEADERS32>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew));
    protect_memory<IMAGE_NT_HEADERS32>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), old_protection);
}

void pe64_parser_t::read_nt_header()
{
    boost::uint32_t old_protection = protect_memory<IMAGE_NT_HEADERS64>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), PAGE_EXECUTE_READWRITE);
    nt_header = *read_memory<IMAGE_NT_HEADERS64>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew));
    protect_memory<IMAGE_NT_HEADERS64>(handle.get(), reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), old_protection);
}