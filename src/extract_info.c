#include "../include/extract_info.h"
#include "../include/pe_analyze.h"

// DOS Header extraction, check the header file for documentation
void print_DOS_header_info(PIMAGE_DOS_HEADER pDosHeader) {
  printf("\033[34me_magic:\033[0m    %d\n", pDosHeader->e_magic);
  printf("\033[34me_cblp:\033[0m     %d\n", pDosHeader->e_cblp);
  printf("\033[34me_cp:\033[0m       %d\n", pDosHeader->e_cp);
  printf("\033[34me_crlc:\033[0m     %d\n", pDosHeader->e_crlc);
  printf("\033[34me_cparhdr:\033[0m  %d\n", pDosHeader->e_cparhdr);
  printf("\033[34me_minalloc:\033[0m %d\n", pDosHeader->e_minalloc);
  printf("\033[34me_maxalloc:\033[0m %d\n", pDosHeader->e_maxalloc);
  printf("\033[34me_ss:\033[0m       %d\n", pDosHeader->e_ss);
  printf("\033[34me_sp:\033[0m       %d\n", pDosHeader->e_sp);
  printf("\033[34me_csum:\033[0m     %d\n", pDosHeader->e_csum);
  printf("\033[34me_ip:\033[0m       %d\n", pDosHeader->e_ip);
  printf("\033[34me_cs:\033[0m       %d\n", pDosHeader->e_cs);
  printf("\033[34me_lfarlc:\033[0m   %d\n", pDosHeader->e_lfarlc);
  printf("\033[34me_ovno:\033[0m     %d\n", pDosHeader->e_ovno);
  printf("\033[34me_res:\033[0m      %d\n", pDosHeader->e_res);
  printf("\033[34me_oemid:\033[0m    %d\n", pDosHeader->e_oemid);
  printf("\033[34me_oeminfo:\033[0m  %d\n", pDosHeader->e_oeminfo);
  printf("\033[34me_res2:\033[0m     %d\n", pDosHeader->e_res2);
  printf("\033[34me_lfanew:\033[0m   %d\n", pDosHeader->e_lfanew);

  return;
}

void print_section_names(PIMAGE_DOS_HEADER pDosHeader,
                         PIMAGE_NT_HEADERS pNtHeaders, FILE *file) {
  // Move to the section headers
  IMAGE_SECTION_HEADER sectionHeader;
  fseek(file, pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);

  // Loop through each section and print its name
  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
    fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file);
    printf("\033[34mSection %d:\033[0m %.8s\n", i + 1, sectionHeader.Name);
  }
}

// Imported DLLs extraction, check the header file for documentation
void print_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders) {
  DWORD importDirectoryRVA =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;

  if (importDirectoryRVA == 0) {
    printf("\033[31mNo import directory found.\033[0m\n");
    return;
  }

  DWORD importDirectoryOffset = rva_to_offset(pNtHeaders, importDirectoryRVA);

  PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirectoryOffset);

  printf("Imported DLLs:\n");

  if (pImportDesc == NULL) {
    printf("Invalid pImportDesc pointer.\n");
    return;
  }

  while (pImportDesc->Name != 0) {
    DWORD nameOffset = rva_to_offset(pNtHeaders, pImportDesc->Name);

    if (nameOffset == 0) {
      printf("\033[31mInvalid DLL name address.\033[0m\n");
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
void print_optional_headers(PIMAGE_NT_HEADERS pNtHeaders) {
  printf("\033[34mMagic:\033[0m 0x%x\n", pNtHeaders->OptionalHeader.Magic);
  printf("\033[34mMajor Linker Version:\033[0m %d\n",
         pNtHeaders->OptionalHeader.MajorLinkerVersion);
  printf("\033[34mMinor Linker Version:\033[0m %d\n",
         pNtHeaders->OptionalHeader.MinorLinkerVersion);
  printf("\033[34mSize of Code:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SizeOfCode);
  printf("\033[34mSize of Initialized Data:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SizeOfInitializedData);
  printf("\033[34mSize of Uninitialized Data:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SizeOfUninitializedData);
  printf("\033[34mAddress of Entry Point:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.AddressOfEntryPoint);
  printf("\033[34mBase of Code:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.BaseOfCode);

  if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    // Print BaseOfData for PE32 only
    printf("\033[34mBase of Data:\033[0m 0x%x\n",
           pNtHeaders->OptionalHeader.BaseOfData);
  }

  printf("\033[34mImage Base:\033[0m 0x%llx\n",
         pNtHeaders->OptionalHeader
             .ImageBase); // 64-bit for PE32+ or 32-bit for PE32
  printf("\033[34mSection Alignment:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SectionAlignment);
  printf("\033[34mFile Alignment:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.FileAlignment);
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
  printf("\033[34mSize of Image:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SizeOfImage);
  printf("\033[34mSize of Headers:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.SizeOfHeaders);
  printf("\033[34mChecksum:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.CheckSum);
  printf("\033[34mSubsystem:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.Subsystem);
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
  printf("\033[34mLoader Flags:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.LoaderFlags);
  printf("\033[34mNumber of Rva and Sizes:\033[0m 0x%x\n",
         pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);
}

// A helper function to list all files in a given directory, check the header
// file for documentation
void listFiles(int verbose, const char *directory, int silent, char *output) {
  WIN32_FIND_DATA findFileData;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  char searchPath[MAX_PATH_LENGTH];
  FILE *json_file;

  snprintf(searchPath, MAX_PATH_LENGTH, "%s\\*", directory);
  hFind = FindFirstFile(searchPath, &findFileData);

  if (strcmp(output, "") != 0) {
    json_file = fopen(output, "a");

    if (!json_file) {
        perror("Failed to open JSON file");
        fclose(json_file);
        return;
    }

    fprintf(json_file, "{");
    fclose(json_file);
  };

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("\033[31mInvalid file handle.\033[0m\n");
    printf("Make sure the directory path is correct and you have the necessary "
           "permissions.\n");
    return;
  } else {
    printf("Listing files in directory: %s\n", directory);
    do {
      if (verbose && !silent) {
        printf("Found: %s\n", findFileData.cFileName);
      }

      if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        printf("Skipping directory: %s\n", findFileData.cFileName);
        continue;
      }

      char filePath[MAX_PATH_LENGTH];
      snprintf(filePath, MAX_PATH_LENGTH, "%s\\%s", directory,
               findFileData.cFileName);

      analyze_pe_file(filePath, verbose, silent, output);
    } while (FindNextFile(hFind, &findFileData) != 0);
    

    if (GetLastError() != ERROR_NO_MORE_FILES) {
      printf("\033[31mError while iterating through directory.\033[0m\n");
    }

    if (strcmp(output, "") != 0) {
      json_file = fopen(output, "a");

      if (!json_file) {
          perror("Failed to open JSON file");
          fclose(json_file);
          return;
      }

      fprintf(json_file, "}");
      fclose(json_file);
    };

    FindClose(hFind);
  }
}

// FUNCTIONS CREATED FOR SAVING TO JSON

void DOS_header_to_json(PIMAGE_DOS_HEADER pDosHeader, FILE *json_file) {
  fprintf(json_file, "  \"DOS_Header\": {\n");
  fprintf(json_file, "    \"e_magic\": %d,\n", pDosHeader->e_magic);
  fprintf(json_file, "    \"e_cblp\": %d,\n", pDosHeader->e_cblp);
  fprintf(json_file, "    \"e_cp\": %d,\n", pDosHeader->e_cp);
  fprintf(json_file, "    \"e_crlc\": %d,\n", pDosHeader->e_crlc);
  fprintf(json_file, "    \"e_cparhdr\": %d,\n", pDosHeader->e_cparhdr);
  fprintf(json_file, "    \"e_minalloc\": %d,\n", pDosHeader->e_minalloc);
  fprintf(json_file, "    \"e_maxalloc\": %d,\n", pDosHeader->e_maxalloc);
  fprintf(json_file, "    \"e_ss\": %d,\n", pDosHeader->e_ss);
  fprintf(json_file, "    \"e_sp\": %d,\n", pDosHeader->e_sp);
  fprintf(json_file, "    \"e_csum\": %d,\n", pDosHeader->e_csum);
  fprintf(json_file, "    \"e_ip\": %d,\n", pDosHeader->e_ip);
  fprintf(json_file, "    \"e_cs\": %d,\n", pDosHeader->e_cs);
  fprintf(json_file, "    \"e_lfarlc\": %d,\n", pDosHeader->e_lfarlc);
  fprintf(json_file, "    \"e_ovno\": %d,\n", pDosHeader->e_ovno);
  fprintf(json_file, "    \"e_res\": %d,\n", pDosHeader->e_res);
  fprintf(json_file, "    \"e_oemid\": %d,\n", pDosHeader->e_oemid);
  fprintf(json_file, "    \"e_oeminfo\": %d,\n", pDosHeader->e_oeminfo);
  fprintf(json_file, "    \"e_res2\": %d,\n", pDosHeader->e_res2);
  fprintf(json_file, "    \"e_lfanew\": %d\n", pDosHeader->e_lfanew);
  fprintf(json_file, "  },\n");
}

void section_names_to_json(PIMAGE_DOS_HEADER pDosHeader,
                           PIMAGE_NT_HEADERS pNtHeaders, FILE *file,
                           FILE *json_file) {
  IMAGE_SECTION_HEADER sectionHeader;
  fseek(file, pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS), SEEK_SET);

  fprintf(json_file, "  \"Sections\": [\n");

  for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
    fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, file);
    fprintf(json_file, "    {\n");
    fprintf(json_file, "      \"Section_%d\": \"%.8s\"\n", i + 1,
            sectionHeader.Name);
    fprintf(json_file, "    }%s\n",
            (i == pNtHeaders->FileHeader.NumberOfSections - 1) ? "" : ",");
  }

  fprintf(json_file, "  ],\n");
}

void imported_dlls_to_json(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders,
                           FILE *json_file) {
  DWORD importDirectoryRVA =
      pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
          .VirtualAddress;

  if (importDirectoryRVA == 0) {
    fprintf(json_file, "  \"Imported_DLLs\": \"No import directory found\",\n");
    return;
  }

  DWORD importDirectoryOffset = rva_to_offset(pNtHeaders, importDirectoryRVA);
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirectoryOffset);

  fprintf(json_file, "  \"Imported_DLLs\": [\n");

  while (pImportDesc->Name != 0) {
    DWORD nameOffset = rva_to_offset(pNtHeaders, pImportDesc->Name);

    if (nameOffset == 0) {
      fprintf(json_file, "    {\n");
      fprintf(json_file, "      \"Error\": \"Invalid DLL name address\"\n");
      fprintf(json_file, "    }\n");

      fprintf(json_file, "  ],");
      break;
    }

    fprintf(json_file, "    {\n");
    fprintf(json_file, "      \"DLL\": \"%s\",\n",
            (char *)(pBase + nameOffset));
    fprintf(json_file, "      \"Functions\": [\n");

    DWORD thunk = pImportDesc->OriginalFirstThunk == 0
                      ? pImportDesc->FirstThunk
                      : pImportDesc->OriginalFirstThunk;
    PIMAGE_THUNK_DATA thunkData =
        (PIMAGE_THUNK_DATA)(pBase + rva_to_offset(pNtHeaders, thunk));

    while (thunkData->u1.AddressOfData != 0) {
      if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        fprintf(json_file, "        {\n");
        fprintf(json_file, "          \"Ordinal\": \"%08x\"\n",
                IMAGE_ORDINAL(thunkData->u1.Ordinal));
        fprintf(json_file, "        }%s\n",
                (thunkData[1].u1.AddressOfData == 0) ? "" : ",");
      } else {
        PIMAGE_IMPORT_BY_NAME pImportByName =
            (PIMAGE_IMPORT_BY_NAME)(pBase +
                                    rva_to_offset(pNtHeaders,
                                                  thunkData->u1.AddressOfData));
        fprintf(json_file, "        {\n");
        fprintf(json_file, "          \"Name\": \"%s\"\n", pImportByName->Name);
        fprintf(json_file, "        }%s\n",
                (thunkData[1].u1.AddressOfData == 0) ? "" : ",");
      }
      thunkData++;
    }

    fprintf(json_file, "      ]\n");
    fprintf(json_file, "    }%s\n", (pImportDesc[1].Name == 0) ? "" : ",");

    pImportDesc++;
  }

  fprintf(json_file, "  ],\n");
}

void optional_headers_to_json(PIMAGE_NT_HEADERS pNtHeaders, FILE *json_file) {
  fprintf(json_file, "  \"Optional_Headers\": {\n");
  fprintf(json_file, "    \"Magic\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.Magic);
  fprintf(json_file, "    \"Major_Linker_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MajorLinkerVersion);
  fprintf(json_file, "    \"Minor_Linker_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MinorLinkerVersion);
  fprintf(json_file, "    \"Size_of_Code\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SizeOfCode);
  fprintf(json_file, "    \"Size_of_Initialized_Data\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SizeOfInitializedData);
  fprintf(json_file, "    \"Size_of_Uninitialized_Data\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SizeOfUninitializedData);
  fprintf(json_file, "    \"Address_of_Entry_Point\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.AddressOfEntryPoint);
  fprintf(json_file, "    \"Base_of_Code\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.BaseOfCode);

  if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    fprintf(json_file, "    \"Base_of_Data\": \"0x%x\",\n",
            pNtHeaders->OptionalHeader.BaseOfData);
  }

  fprintf(json_file, "    \"Image_Base\": \"0x%llx\",\n",
          pNtHeaders->OptionalHeader.ImageBase);
  fprintf(json_file, "    \"Section_Alignment\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SectionAlignment);
  fprintf(json_file, "    \"File_Alignment\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.FileAlignment);
  fprintf(json_file, "    \"Major_OS_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MajorOperatingSystemVersion);
  fprintf(json_file, "    \"Minor_OS_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
  fprintf(json_file, "    \"Major_Image_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MajorImageVersion);
  fprintf(json_file, "    \"Minor_Image_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MinorImageVersion);
  fprintf(json_file, "    \"Major_Subsystem_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MajorSubsystemVersion);
  fprintf(json_file, "    \"Minor_Subsystem_Version\": %d,\n",
          pNtHeaders->OptionalHeader.MinorSubsystemVersion);
  fprintf(json_file, "    \"Win32_Version_Value\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.Win32VersionValue);
  fprintf(json_file, "    \"Size_of_Image\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SizeOfImage);
  fprintf(json_file, "    \"Size_of_Headers\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.SizeOfHeaders);
  fprintf(json_file, "    \"Checksum\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.CheckSum);
  fprintf(json_file, "    \"Subsystem\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.Subsystem);
  fprintf(json_file, "    \"DLL_Characteristics\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.DllCharacteristics);
  fprintf(json_file, "    \"Size_of_Stack_Reserve\": \"0x%llx\",\n",
          pNtHeaders->OptionalHeader.SizeOfStackReserve);
  fprintf(json_file, "    \"Size_of_Stack_Commit\": \"0x%llx\",\n",
          pNtHeaders->OptionalHeader.SizeOfStackCommit);
  fprintf(json_file, "    \"Size_of_Heap_Reserve\": \"0x%llx\",\n",
          pNtHeaders->OptionalHeader.SizeOfHeapReserve);
  fprintf(json_file, "    \"Size_of_Heap_Commit\": \"0x%llx\",\n",
          pNtHeaders->OptionalHeader.SizeOfHeapCommit);
  fprintf(json_file, "    \"Loader_Flags\": \"0x%x\",\n",
          pNtHeaders->OptionalHeader.LoaderFlags);
  fprintf(json_file, "    \"Number_of_Rva_and_Sizes\": \"0x%x\"\n",
          pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);
  fprintf(json_file, "  },\n");
}
