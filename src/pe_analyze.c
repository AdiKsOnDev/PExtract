#include "../include/pe_analyze.h"
#include "../include/disassembly.h"

void analyze_pe_file(char *pe_path, int verbose) {
  printf("Analysing file --> %s\n", pe_path)
  printf("==============================================\n")

  HANDLE hFile = CreateFile(pe_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  FILE *file = fopen(pe_path, "rb");

  if (hFile == INVALID_HANDLE_VALUE) {
    printf("\033[31mFailed to open file.\n\033[0m");
    return;
  }

  HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hMap == NULL) {
    CloseHandle(hFile);
    printf("\033[31mFailed to create file mapping.\n\033[0m");
    return;
  }

  LPVOID pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  if (pBase == NULL) {
    CloseHandle(hMap);
    CloseHandle(hFile);
    printf("\033[31mFailed to map view of file.\n\033[0m");
    return;
  }

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("\033[31mNot a valid DOS file.\n\033[0m");
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return;
  }

  extract_DOS_header_info(pDosHeader);

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("\033[31mNot a valid NT file.\n\033[0m");
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return;
  }

  extract_imported_dlls((PBYTE)pBase, pNtHeaders);
  extract_section_names(pDosHeader, pNtHeaders, file);
  extract_optional_headers(pNtHeaders);

  UnmapViewOfFile(pBase);
  CloseHandle(hMap);
  CloseHandle(hFile);
}
