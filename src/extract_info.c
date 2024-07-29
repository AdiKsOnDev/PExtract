#include "../include/extract_info.h"
#include "../include/pe_analyze.h"
#include <stdio.h>
#include <string.h>

void extract_DOS_header_info(PIMAGE_DOS_HEADER pDosHeader, char *output_file,
                             char *pe_file_name) {
  if (strcmp(output_file, "") != 0) {
    FILE *file = fopen(output_file, "a");
    char *values[20];

    values[0] = pe_file_name;

    sprintf(values[1], "%d", pDosHeader->e_magic);
    sprintf(values[2], "%d", pDosHeader->e_cblp);
    sprintf(values[3], "%d", pDosHeader->e_cp);
    sprintf(values[4], "%d", pDosHeader->e_crlc);
    sprintf(values[5], "%d", pDosHeader->e_cparhdr);
    sprintf(values[6], "%d", pDosHeader->e_minalloc);
    sprintf(values[7], "%d", pDosHeader->e_maxalloc);
    sprintf(values[8], "%d", pDosHeader->e_ss);
    sprintf(values[9], "%d", pDosHeader->e_sp);
    sprintf(values[10], "%d", pDosHeader->e_csum);
    sprintf(values[11], "%d", pDosHeader->e_ip);
    sprintf(values[12], "%d", pDosHeader->e_cs);
    sprintf(values[13], "%d", pDosHeader->e_lfarlc);
    sprintf(values[14], "%d", pDosHeader->e_ovno);
    sprintf(values[15], "%d", pDosHeader->e_res);
    sprintf(values[16], "%d", pDosHeader->e_oemid);
    sprintf(values[17], "%d", pDosHeader->e_oeminfo);
    sprintf(values[18], "%d", pDosHeader->e_res2);
    sprintf(values[19], "%d", pDosHeader->e_lfanew);

    if (file == NULL) {
      perror("Error opening file");

      return;
    }

    for (int index = 0; index < 20; index++) {
      fprintf(file, "%s", values[index]);

      if (index < 19) {
        fprintf(file, ",");
      }
    }
    fprintf(file, "\n");

    fclose(file);
  }

  printf("e_magic:    %d\n", pDosHeader->e_magic);
  printf("e_cblp:     %d\n", pDosHeader->e_cblp);
  printf("e_cp:       %d\n", pDosHeader->e_cp);
  printf("e_crlc:     %d\n", pDosHeader->e_crlc);
  printf("e_cparhdr:  %d\n", pDosHeader->e_cparhdr);
  printf("e_minalloc: %d\n", pDosHeader->e_minalloc);
  printf("e_maxalloc: %d\n", pDosHeader->e_maxalloc);
  printf("e_ss:       %d\n", pDosHeader->e_ss);
  printf("e_sp:       %d\n", pDosHeader->e_sp);
  printf("e_csum:     %d\n", pDosHeader->e_csum);
  printf("e_ip:       %d\n", pDosHeader->e_ip);
  printf("e_cs:       %d\n", pDosHeader->e_cs);
  printf("e_lfarlc:   %d\n", pDosHeader->e_lfarlc);
  printf("e_ovno:     %d\n", pDosHeader->e_ovno);
  printf("e_res:      %d\n", pDosHeader->e_res);
  printf("e_oemid:    %d\n", pDosHeader->e_oemid);
  printf("e_oeminfo:  %d\n", pDosHeader->e_oeminfo);
  printf("e_res2:     %d\n", pDosHeader->e_res2);
  printf("e_lfanew:   %d\n", pDosHeader->e_lfanew);

  return;
}

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
