#include "../include/disassembly.h"

/* Converts RVA to file offset
 * -------------------------------------------
 * param: pNtHeaders, NT headers of a PE file
 * param: rva, DWORD typed RVA to be converted
 *
 * return: DWORD offset
 */
DWORD rva_to_offset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
  if (rva == 0 || rva >= pNtHeaders->OptionalHeader.SizeOfImage) {
      return 0; // Invalid offset
  }
  
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);

  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, section++) {
    if (rva >= section->VirtualAddress &&
        rva < section->VirtualAddress + section->Misc.VirtualSize) {
      return (rva - section->VirtualAddress) + section->PointerToRawData;
    }
  }
  return 0;
}
