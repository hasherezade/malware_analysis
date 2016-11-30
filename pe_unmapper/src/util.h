#pragma once

#include <windows.h>
#include <stdio.h>

bool validate_ptr(LPVOID buffer_bgn, SIZE_T buffer_size, LPVOID field_bgn, SIZE_T field_size);