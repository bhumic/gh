#pragma once

#include "util.h"

class pe_parser_t;
class pe32_parser_t;
class pe64_parser_t;

pe_parser_t* create_pe_parser(PROCESS_INFO& process_info);

class pe_parser_t
{
public:
    pe_parser_t(PROCESS_INFO& _proc_info)
        : process_info(_proc_info) 
    {}

    void obtain_handle();

    void read_dos_header();
    virtual void read_nt_header() = 0;

    IMAGE_DOS_HEADER dos_header;

protected:
    // process handle
    boost::shared_ptr<void> handle;
    // process info
    const PROCESS_INFO process_info;
};

class pe32_parser_t : public pe_parser_t
{
public:
    pe32_parser_t(PROCESS_INFO& process_info)
        : pe_parser_t(process_info)
    {}

    virtual void read_nt_header();

    IMAGE_NT_HEADERS32 nt_header;
};

class pe64_parser_t : public pe_parser_t
{
public:
    pe64_parser_t(PROCESS_INFO& process_info)
        : pe_parser_t(process_info)
    {}

    virtual void read_nt_header();

    IMAGE_NT_HEADERS64 nt_header;
};