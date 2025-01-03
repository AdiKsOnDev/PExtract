#include "../include/extract_info.h"
#include "../include/pe_analyze.h"

// DOS Header extraction, check the header file for documentation
void extract_DOS_header_info(PIMAGE_DOS_HEADER pDosHeader) {
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

void extract_section_names(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeaders, FILE *file) {
  // Move to the section headers
  IMAGE_SECTION_HEADER sectionHeader;
  fseek(file, pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);

  // Loop through each section and print its name
  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
    fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file);
    printf("Section %d: %.8s\n", i + 1, sectionHeader.Name);
  }
}

// Imported DLLs extraction, check the header file for documentation
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders) {
  DWORD importDirectoryRVA =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;

  if (importDirectoryRVA == 0) {
    printf("No import directory found.\n");
    return;
  }

  DWORD importDirectoryOffset = rva_to_offset(pNtHeaders, importDirectoryRVA);

  PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirectoryOffset);

  printf("Imported DLLs:\n");
  while (pImportDesc->Name != 0) {
    DWORD nameOffset = rva_to_offset(pNtHeaders, pImportDesc->Name);

    if (nameOffset == 0) {
      printf("Invalid DLL name address.\n");
      break;
    }
    printf(" \033[34m%s\033[0m\n", (char *)(pBase + nameOffset));

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

// Optional Headers extraction, check the header file for documentation
void extract_optional_headers(PIMAGE_NT_HEADERS pNtHeaders) {
   printf("\033[34mMagic:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.Magic);
   printf("\033[34mMajor Linker Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MajorLinkerVersion);
   printf("\033[34mMinor Linker Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MinorLinkerVersion);
   printf("\033[34mSize of Code:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.SizeOfCode);
   printf("\033[34mSize of Initialized Data:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.SizeOfInitializedData);
   printf("\033[34mSize of Uninitialized Data:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.SizeOfUninitializedData);
   printf("\033[34mAddress of Entry Point:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.AddressOfEntryPoint);
   printf("\033[34mBase of Code:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.BaseOfCode);
  
   if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
     // Print BaseOfData for PE32 only
     printf("\033[34mBase of Data:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.BaseOfData);
   }
  
   printf("\033[34mImage Base:\033[0m 0x%llx\n",
          pNtHeaders->OptionalHeader
              .ImageBase); // 64-bit for PE32+ or 32-bit for PE32
   printf("\033[34mSection Alignment:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.SectionAlignment);
   printf("\033[34mFile Alignment:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.FileAlignment);
   printf("\033[34mMajor OS Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MajorOperatingSystemVersion);
   printf("\033[34mMinor OS Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
   printf("\033[34mMajor Image Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MajorImageVersion);
   printf("\033[34mMinor Image Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MinorImageVersion);
   printf("\033[34mMajor Subsystem Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MajorSubsystemVersion);
   printf("\033[34mMinor Subsystem Version:\033[0m %d\n",
          pNtHeaders->OptionalHeader.MinorSubsystemVersion);
   printf("\033[34mWin32 Version Value:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.Win32VersionValue); // Should be 0
   printf("\033[34mSize of Image:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.SizeOfImage);
   printf("\033[34mSize of Headers:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.SizeOfHeaders);
   printf("\033[34mChecksum:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.CheckSum);
   printf("\033[34mSubsystem:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.Subsystem);
   printf("\033[34mDLL Characteristics:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.DllCharacteristics);
   printf("\033[34mSize of Stack Reserve:\033[0m 0x%llx\n",
          pNtHeaders->OptionalHeader.SizeOfStackReserve); // 64-bit for PE32+
   printf("\033[34mSize of Stack Commit:\033[0m 0x%llx\n",
          pNtHeaders->OptionalHeader.SizeOfStackCommit); // 64-bit for PE32+
   printf("\033[34mSize of Heap Reserve:\033[0m 0x%llx\n",
          pNtHeaders->OptionalHeader.SizeOfHeapReserve); // 64-bit for PE32+
   printf("\033[34mSize of Heap Commit:\033[0m 0x%llx\n",
          pNtHeaders->OptionalHeader.SizeOfHeapCommit); // 64-bit for PE32+
   printf("\033[34mLoader Flags:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.LoaderFlags);
   printf("\033[34mNumber of Rva and Sizes:\033[0m 0x%x\n",
          pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);
}

// A helper function to list all files in a given directory, check the header
// file for documentation
void listFiles(int verbose, const char *directory) {
  WIN32_FIND_DATA findFileData;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  char searchPath[MAX_PATH_LENGTH];

  snprintf(searchPath, MAX_PATH_LENGTH, "%s\\*", directory);
  hFind = FindFirstFile(searchPath, &findFileData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("Invalid file handle.");
    printf("Make sure the directory path is correct and you have the necessary "
           "permissions.\n");

    return;
  } else {
    printf("Listing files in directory: %s\n", directory);
    do {
      if (verbose == 1) {
        printf("Found: %s\n", findFileData.cFileName);
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          printf("Skipping directory: %s\n", findFileData.cFileName);
          continue;
        }
      }

      char filePath[MAX_PATH_LENGTH];
      snprintf(filePath, MAX_PATH_LENGTH, "%s\\%s", directory,
               findFileData.cFileName);

      analyze_pe_file(filePath, verbose);
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
  }
}
