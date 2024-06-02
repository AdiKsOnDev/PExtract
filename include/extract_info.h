#ifndef EXTRACT_FUNCTIONS
#include <windows.h>

// Get the list of imported DLLs from a PE file
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

// Function that extracts system calls using Capstone disassembler
void extract_system_calls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

#endif // !EXTRACT_FUNCTIONS
#define EXTRACT_FUNCTIONS
