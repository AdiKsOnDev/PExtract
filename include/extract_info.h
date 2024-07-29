#ifndef EXTRACT_FUNCTIONS
#define EXTRACT_FUNCTIONS
#define MAX_PATH_LENGTH 260

#include "disassembly.h"
#include <stdio.h>
#include <windows.h>

/* Given the DOS Header of a PE file,
 * extracts all the info from PIMAGE_DOS_HEADER structure
 * -------------------------------------------
 * param: pDosHeader, DOS Header of a PE file
 * param: output_file, Pass an empty string if no output file is needed
 * param: pe_file_name, Name of the PE file associated with the given DOS header
 *
 * return: void
 */
void extract_DOS_header_info(PIMAGE_DOS_HEADER pDosHeader, char *output_file,
                             char *pe_file_name);

/* Given pBase and Headers of a PE file,
 * extracts the DLLs imported in the executable
 * -------------------------------------------
 * param: pBase,
 * param: pNtHeaders, NT Headers of a PE file
 *
 * return: void
 */
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

/* Given the Headers of a PE file, extracts and prints out
 * crucial system information, such as OS, Subsystem, etc.
 * -------------------------------------------
 * param: pNtHeaders, NT Headers of a PE file
 *
 * return: void
 */
void extract_pe_system_info(PIMAGE_NT_HEADERS pNtHeaders);

#endif // !EXTRACT_FUNCTIONS
