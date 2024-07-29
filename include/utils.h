#ifndef UTILS
#define UTILS 

#include "pe_analyze.h"
#include <stdio.h>
#include <windows.h>

/* Function to write data from the given 
 * 1D array into a csv as if it was a 2D array
 * Function expects an array that was flattened
 * from 2D into 1D. [[1,2,3], [4,5,6]] --> [1,2,3, 4,5,6]
 *
 * param: filename, A string containing the name of a file
 * param: **data, An array of rows to write in a given CSV
 * param: rows, Number of rows in the given array
 * param: cols, Number of columns in the given array
 *
 * return: void
 */
void write_csv(const char *filename, const char **data, int rows, int cols);

/* Given a path to directory, return a list of all files 
 * in it.
 * -------------------------------------------
 *  param: directory, String containing the path to a directory
 *  param: verbose, Pass 1 if verbose mode is needed
 *
 *  return: void
 */
void listFiles(int verbose, const char* directory, char *output_file);

#endif // !UTILS
