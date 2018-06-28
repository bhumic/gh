
#include "util.h"
#include "pe.h"

int main(int argc, char* argv[])
{
    PROCESS_INFO process_info;
    get_process_info("chrome.exe", process_info);

    boost::shared_ptr<void> handle = get_process_handle(process_info.pid);
    
    pe_parser_t* parser = create_pe_parser(process_info);
    parser->obtain_handle();
    parser->read_dos_header();
    parser->read_nt_header();
    
    boost::uint32_t old_protection = protect_memory<boost::uint32_t>(handle.get(), (LPVOID)process_info.base, PAGE_EXECUTE_READWRITE);
    DWORD first = *read_memory<DWORD>(handle.get(), (LPVOID)process_info.base);
    protect_memory<boost::uint32_t>(handle.get(), (LPVOID)process_info.base, old_protection);
    system("pause");
    return 0;
}