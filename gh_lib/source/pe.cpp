#include "pe.h"

namespace gh
{
    namespace pe
    {
        pe_parser_t* create_pe_parser(gh::process::PROCESS_INFO& process_info)
        {
            if (process_info.is64bit)
                return new pe64_parser_t(process_info);
            return new pe32_parser_t(process_info);
        }


        void pe_parser_t::obtain_handle()
        {
            this->handle = gh::process::get_process_handle(this->process_info.pid);
        }

        void pe_parser_t::read_dos_header()
        {
            gh::memory::read_structure<IMAGE_DOS_HEADER>(this->handle, this->process_info.base, this->dos_header);
        }

        void pe32_parser_t::read_nt_header()
        {
            gh::memory::read_structure<IMAGE_NT_HEADERS32>(this->handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), this->nt_header);
        }

        void pe64_parser_t::read_nt_header()
        {
            gh::memory::read_structure<IMAGE_NT_HEADERS64>(this->handle, reinterpret_cast<LPVOID>(reinterpret_cast<char*>(process_info.base) + dos_header.e_lfanew), this->nt_header);
        }
    }
}