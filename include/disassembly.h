#ifndef DISASSEMBLY
#define DISASSEMBLY

#include <windows.h>

/* Converts RVA to file offset
 * -------------------------------------------
 * param: pNtHeaders, NT headers of a PE file
 * param: rva, DWORD typed RVA to be converted
 *
 * return: DWORD offset
 */
DWORD rva_to_offset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva); 

/* Given pBase and Headers of a PE file,
 * extracts the system calls utilized in the 
 * executable. Uses capstone library
 * -------------------------------------------
 * param: pbase,
 * param: pNtHeaders, Headers of a PE file
 *
 * return: void
 */ 
void extract_system_calls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

#endif // !DISASSEMBLY
