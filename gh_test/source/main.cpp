#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "util.h"
#include "pe.h"
#include "inject.h"
#include "shellcode.h"
#include "hook.h"

int main(int argc, char* argv[])
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    // Test process info data retrieval
    gh::process::PROCESS_INFO process_info;
    gh::process::get_process_info("vf_sample.exe", process_info);
    
    // Test if parser for PE is working
    gh::pe::pe_parser_t* parser = gh::pe::create_pe_parser(process_info);
    parser->obtain_handle();
    parser->read_dos_header();
    parser->read_nt_header();
    delete parser;

    // Test the injector modules
    //gh::injector::injector_t injector;
    //injector.inject_dll(process_info, "E:\\local_repository\\gh\\msgbox_dll\\Release\\msgbox_dll.dll");
    //injector.eject_dll(process_info, "msgbox_dll.dll");

    // Test NOPing
    // gh::memory::write_nop<30>(process_info.handle, process_info.base);

    // Test near call hooking
    //LPVOID orig_call = gh::hooking::hook_near_call<boost::int32_t>(process_info.handle, (LPVOID)0x0007ffb27f8da5d, (LPVOID)0x0007ffb27f8da45);

    // Test VF hooking
    LPVOID orig_vf = gh::hooking::hook_virtual_function(process_info.handle, (LPVOID)0x00653090, 1, (LPVOID)0x00b31020);

    CloseHandle(process_info.handle);
    _CrtDumpMemoryLeaks();
    system("pause");
    return 0;
}