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
 */
void print_DOS_header_info(PIMAGE_DOS_HEADER pDosHeader);

/* Given pBase and NT Headers of a PE file,
 * extracts the DLLs imported in the executable
 * -------------------------------------------
 * param: pBase,
 * param: pNtHeaders, NT Headers of a PE file
 *
 * return: void
 */
void print_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

/* Given DOS and NT Headers of a PE file,
 * extracts the section names used in the executable
 * -------------------------------------------
 * param: pDosHeader, DOS Header of a PE file
 * param: pNtHeaders, NT Headers of a PE file
 * param: file, Pointer to the executable file
 *
 * return: void
 */
void print_section_names(PIMAGE_DOS_HEADER pDosHeader,
                           PIMAGE_NT_HEADERS pNtHeaders, 
                           FILE *file);

/* Given the Headers of a PE file, extracts and prints out
 * OptionalHeader fields
 * -------------------------------------------
 * param: pNtHeaders, NT Headers of a PE file
 *
 * return: void
 */
void print_optional_headers(PIMAGE_NT_HEADERS pNtHeaders);

/* Given a path to directory, return a list of all files
 * in it.
 * -------------------------------------------
 *  param: directory, String containing the path to a directory
 *  param: verbose, Pass 1 if verbose mode is needed
 *
 *  return: void
 */
void listFiles(int verbose, const char *directory, int silent, char *output);

#endif // !EXTRACT_FUNCTIONS
