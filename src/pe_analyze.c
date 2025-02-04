#include <stdio.h>
#include <string.h>
#include "../include/pe_analyze.h"
#include "../include/disassembly.h"

void analyze_pe_file(char *pe_path, int verbose, int silent, char *output) {
  if (!silent) {
    printf("\033[32mAnalysing file --> %s\n\033[0m", pe_path);
    printf("==============================================\n");
  }

  HANDLE hFile = CreateFile(pe_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  FILE *file = fopen(pe_path, "rb");
  FILE *json_file;

  if (strcmp(output, "") != 0) {
    json_file = fopen(output, "a");

    if (!json_file) {
        perror("Failed to open JSON file");
        return;
    }

    fprintf(json_file, "%s: {\n", pe_path);
  };

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

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);

  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("\033[31mNot a valid NT file.\n\033[0m");
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return;
  }

  if (!silent) {
    print_DOS_header_info(pDosHeader);
    print_imported_dlls((PBYTE)pBase, pNtHeaders);
    if (verbose) {
      print_section_names(pDosHeader, pNtHeaders, file);
      print_optional_headers(pNtHeaders);
    }
  }

  if (strcmp(output, "") != 0) {
    DOS_header_to_json(pDosHeader, json_file);
    imported_dlls_to_json(pBase, pNtHeaders, json_file);
    if (verbose) {
      section_names_to_json(pDosHeader, pNtHeaders, file, json_file);
      optional_headers_to_json(pNtHeaders, json_file);
    }

    fprintf(json_file, "},");
  }

  UnmapViewOfFile(pBase);
  CloseHandle(hMap);
  CloseHandle(hFile);
}
