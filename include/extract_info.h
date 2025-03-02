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
                         PIMAGE_NT_HEADERS pNtHeaders, FILE *file);

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

/* Given the DOS Header of a PE file,
 * extracts all the info from PIMAGE_DOS_HEADER structure
 * and saves it to a JSON file
 * -------------------------------------------
 * param: pDosHeader, DOS Header of a PE file
 * param: json_file, JSON file to be written to
 *
 * return: void
 */
void DOS_header_to_json(PIMAGE_DOS_HEADER pDosHeader, FILE *json_file);

/* Given DOS and NT Headers of a PE file,
 * extracts the section names used in the executable
 * and saves them to a JSON file
 * -------------------------------------------
 * param: pDosHeader, DOS Header of a PE file
 * param: pNtHeaders, NT Headers of a PE file
 * param: file, Pointer to the executable file
 * param: json_file, JSON file to be written to
 *
 * return: void
 */
void section_names_to_json(PIMAGE_DOS_HEADER pDosHeader,
                           PIMAGE_NT_HEADERS pNtHeaders, FILE *file,
                           FILE *json_file);

/* Given pBase and NT Headers of a PE file,
 * extracts the DLLs imported in the executable
 * and saves them into a JSON file
 * -------------------------------------------
 * param: pBase,
 * param: pNtHeaders, NT Headers of a PE file
 * param: json_file, JSON file to be written to
 *
 * return: void
 */
void imported_dlls_to_json(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders,
                           FILE *json_file);

/* Given the Headers of a PE file, extracts and saves
 * OptionalHeader fields into a JSON
 * -------------------------------------------
 * param: pNtHeaders, NT Headers of a PE file
 * param: json_file, JSON file to be written to
 *
 * return: void
 */
void optional_headers_to_json(PIMAGE_NT_HEADERS pNtHeaders, FILE *json_file);

#endif // !EXTRACT_FUNCTIONS
