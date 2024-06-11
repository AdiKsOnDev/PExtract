#include "../include/extract_info.h"

void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders) {
  DWORD importDirectoryRVA =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;
  if (importDirectoryRVA == 0) {
    printf("No import directory found.\n");
    return;
  }

  DWORD importDirectoryOffset = rva_to_offset(pNtHeaders, importDirectoryRVA);
  if (importDirectoryOffset == 0) {
    printf("Invalid import directory offset.\n");
    return;
  }

  PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirectoryOffset);
  if (pImportDesc == NULL) {
    printf("No import table found.\n");
    return;
  }

  printf("Imported DLLs:\n");
  while (pImportDesc->Name != 0) {
    DWORD nameOffset = rva_to_offset(pNtHeaders, pImportDesc->Name);
    if (nameOffset == 0) {
      printf("Invalid DLL name address.\n");
      break;
    }
    printf("  %s\n", (char *)(pBase + nameOffset));

    DWORD thunk = pImportDesc->OriginalFirstThunk == 0
                      ? pImportDesc->FirstThunk
                      : pImportDesc->OriginalFirstThunk;
    PIMAGE_THUNK_DATA thunkData =
        (PIMAGE_THUNK_DATA)(pBase + rva_to_offset(pNtHeaders, thunk));

    // DLL exported functions
    while (thunkData->u1.AddressOfData != 0) {
      if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // If it's an ordinal import
        printf("\t\tOrdinal: %08x\n", IMAGE_ORDINAL(thunkData->u1.Ordinal));
      } else {
        // If it's a named import
        PIMAGE_IMPORT_BY_NAME pImportByName =
            (PIMAGE_IMPORT_BY_NAME)(pBase +
                                    rva_to_offset(pNtHeaders,
                                                  thunkData->u1.AddressOfData));
        printf("\t\t%s\n", pImportByName->Name);
      }

      thunkData++;
    }

    pImportDesc++;
  }
}

// Function to extract system information from PE headers
void extract_pe_system_info(PIMAGE_NT_HEADERS pNtHeaders) {
  printf("System Information:\n");
  printf("  Operating System Version: %d.%d\n",
         pNtHeaders->OptionalHeader.MajorOperatingSystemVersion,
         pNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
  printf("  Image Version: %d.%d\n",
         pNtHeaders->OptionalHeader.MajorImageVersion,
         pNtHeaders->OptionalHeader.MinorImageVersion);
  printf("  Subsystem Version: %d.%d\n",
         pNtHeaders->OptionalHeader.MajorSubsystemVersion,
         pNtHeaders->OptionalHeader.MinorSubsystemVersion);
  printf("  Subsystem: %d\n", pNtHeaders->OptionalHeader.Subsystem);
}
