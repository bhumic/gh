#pragma once

#include "util.h"

template<typename T>
class pe_parser
{
public:
    pe_parser(boost::shared_ptr<void>& _handle)
        : handle(_handle) {}

    IMAGE_DOS_HEADER dos_header;
    T nt_header;

private:
    // process handle
    const boost::shared_ptr<void>& handle;
};