#include "../include/disassembly.h"

// Function to convert RVA to file offset
DWORD rva_to_offset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);

  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, section++) {
    if (rva >= section->VirtualAddress &&
        rva < section->VirtualAddress + section->Misc.VirtualSize) {
      return (rva - section->VirtualAddress) + section->PointerToRawData;
    }
  }
  return 0;
}
