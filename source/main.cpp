#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "util.h"
#include "pe.h"
#include "inject.h"
#include "shellcode.h"

int main(int argc, char* argv[])
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    // Test process info data retrieval
    PROCESS_INFO process_info;
    get_process_info("ConEmu.exe", process_info);
    
    // Test if parser for PE is working
    pe_parser_t* parser = create_pe_parser(process_info);
    parser->obtain_handle();
    parser->read_dos_header();
    parser->read_nt_header();
    delete parser;

    // Test the injector modules
    injector_t injector;
    injector.inject_shellcode_crt(process_info, shellcode_msgboxa_32);

    std::vector<BYTE> shellcode(shellcode_msgboxa_32.begin(), shellcode_msgboxa_32.end() - 1);
    injector.inject_shellcode_mth(process_info, shellcode);

    _CrtDumpMemoryLeaks();
    system("pause");
    return 0;
}