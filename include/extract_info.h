#ifndef EXTRACT_FUNCTIONS
#define EXTRACT_FUNCTIONS

#include <windows.h>
#include <capstone/capstone.h>

/* Given pBase and Headers of a PE file,
 * extracts the DLLs imported in the executable
 * -------------------------------------------
 * param: pBase,
 * param: pNtHeaders, Headers of a PE file
 *
 * return: void
 */
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

// Function that extracts system calls using Capstone disassembler
void extract_system_calls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

#endif // !EXTRACT_FUNCTIONS
