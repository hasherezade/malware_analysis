#pragma once
#include <Windows.h>

BYTE* get_nt_hrds(BYTE *pe_buffer);
IMAGE_NT_HEADERS32* get_nt_hrds32(BYTE *pe_buffer);
IMAGE_NT_HEADERS64* get_nt_hrds64(BYTE *pe_buffer);

IMAGE_DATA_DIRECTORY* get_pe_directory(PVOID pe_buffer, DWORD dir_id);
bool is64bit(BYTE *pe_buffer);