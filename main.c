#include "include/disassembly.h"
#include "include/extract_info.h"

int main() {
  HANDLE hFile = CreateFile(pe_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    printf("Failed to open file.\n");
    return;
  }

  HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
  if (hMap == NULL) {
    CloseHandle(hFile);
    printf("Failed to create file mapping.\n");
    return;
  }

  LPVOID pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
  if (pBase == NULL) {
    CloseHandle(hMap);
    CloseHandle(hFile);
    printf("Failed to map view of file.\n");
    return;
  }

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
  if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Not a valid DOS file.\n");
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return;
  }

  PIMAGE_NT_HEADERS pNtHeaders =
      (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);
  if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
    printf("Not a valid NT file.\n");
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return;
  }

  printf("Optional Header Magic: 0x%04x\n", pNtHeaders->OptionalHeader.Magic);
  printf("Number of Data Directories: %d\n",
         pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);
  printf("Import Directory RVA: 0x%08x\n",
         pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
             .VirtualAddress);
  printf("Import Directory Size: 0x%08x\n",
         pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
             .Size);

  extract_imported_dlls((PBYTE)pBase, pNtHeaders);
  extract_pe_system_info(pNtHeaders);

  UnmapViewOfFile(pBase);
  CloseHandle(hMap);
  CloseHandle(hFile);

  return 0;
}
