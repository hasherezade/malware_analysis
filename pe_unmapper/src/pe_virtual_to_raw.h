#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

// Map virtual image of PE to into raw:
bool sections_virtual_to_raw(BYTE* in_buffer, SIZE_T virtual_size, OUT BYTE* out_buffer, OUT SIZE_T *raw_size_ptr);
