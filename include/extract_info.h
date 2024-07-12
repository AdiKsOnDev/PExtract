#ifndef EXTRACT_FUNCTIONS
#define EXTRACT_FUNCTIONS
#define MAX_PATH_LENGTH 260

#include <windows.h>
#include <stdio.h>
#include "disassembly.h"

/* Given pBase and Headers of a PE file,
 * extracts the DLLs imported in the executable
 * -------------------------------------------
 * param: pBase,
 * param: pNtHeaders, Headers of a PE file
 *
 * return: void
 */
void extract_imported_dlls(PBYTE pBase, PIMAGE_NT_HEADERS pNtHeaders);

/* Given the Headers of a PE file, extracts and prints out
 * crucial system information, such as OS, Subsystem, etc.
 * -------------------------------------------
 * param: pNtHeaders, Headers of a PE file
 *
 * return: void
 */ 
void extract_pe_system_info(PIMAGE_NT_HEADERS pNtHeaders); 

/* Given a path to directory, return a list of all files 
 * in it.
 * -------------------------------------------
 *  param: directory, String containing the path to a directory
 *
 *  return: void
 */
void listFiles(const char* directory);

#endif // !EXTRACT_FUNCTIONS
