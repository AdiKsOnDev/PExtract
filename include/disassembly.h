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
#endif // !DISASSEMBLY
