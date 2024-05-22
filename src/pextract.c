#include <stdio.h>
#include <windows.h>

// Function to convert RVA to file offset
DWORD rva_to_offset(PIMAGE_NT_HEADERS pNtHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return (rva - section->VirtualAddress) + section->PointerToRawData;
        }
    }
    return 0;
}

// Function to extract imported DLLs
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD importDirectoryRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirectoryRVA == 0) {
        printf("No import directory found.\n");
        return;
    }

    DWORD importDirectoryOffset = rva_to_offset(pNtHeaders, importDirectoryRVA);
    if (importDirectoryOffset == 0) {
        printf("Invalid import directory offset.\n");
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + importDirectoryOffset);
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
        printf("  %s\n", (char*)(pBase + nameOffset));
        pImportDesc++;
    }
}

// Function to extract system information from PE headers
void extract_pe_system_info(PIMAGE_NT_HEADERS pNtHeaders) {
    printf("System Information:\n");
    printf("  Operating System Version: %d.%d\n", pNtHeaders->OptionalHeader.MajorOperatingSystemVersion, pNtHeaders->OptionalHeader.MinorOperatingSystemVersion);
    printf("  Image Version: %d.%d\n", pNtHeaders->OptionalHeader.MajorImageVersion, pNtHeaders->OptionalHeader.MinorImageVersion);
    printf("  Subsystem Version: %d.%d\n", pNtHeaders->OptionalHeader.MajorSubsystemVersion, pNtHeaders->OptionalHeader.MinorSubsystemVersion);
    printf("  Subsystem: %d\n", pNtHeaders->OptionalHeader.Subsystem);
}

void analyze_pe_file(char* pe_path) {
    HANDLE hFile = CreateFile(pe_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("Not a valid NT file.\n");
        UnmapViewOfFile(pBase);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return;
    }

    printf("Optional Header Magic: 0x%04x\n", pNtHeaders->OptionalHeader.Magic);
    printf("Number of Data Directories: %d\n", pNtHeaders->OptionalHeader.NumberOfRvaAndSizes);
    printf("Import Directory RVA: 0x%08x\n", pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("Import Directory Size: 0x%08x\n", pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    extract_imported_dlls((PBYTE)pBase, pNtHeaders);
    extract_pe_system_info(pNtHeaders);

    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
}

int main() {
    char pe_path[] = "pefile.exe";
    analyze_pe_file(pe_path);
    return 0;
}

