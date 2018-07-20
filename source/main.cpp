#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "util.h"
#include "pe.h"

int main(int argc, char* argv[])
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    PROCESS_INFO process_info;
    get_process_info("chrome.exe", process_info);
    
    pe_parser_t* parser = create_pe_parser(process_info);
    parser->obtain_handle();
    parser->read_dos_header();
    parser->read_nt_header();
    delete parser;


    protect_memory(process_info.handle.get(), process_info.base, 0x1000, PAGE_EXECUTE_READWRITE);

    _CrtDumpMemoryLeaks();
    system("pause");
    return 0;
}