#include "../include/utils.h"

void write_csv(const char *filename, const char **data, int rows, int cols) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Iterate through the array and write each row to the file
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            fprintf(file, "%s", data[i * cols + j]); // This calculates the correct index for a 1D 
                                                     // array that represents a 2D array (flattening)
            if (j < cols - 1) {
                fprintf(file, ",");
            }
        }
        fprintf(file, "\n");
    }

    // Close the file
    fclose(file);
}

void listFiles(int verbose, const char *directory) {
  WIN32_FIND_DATA findFileData;
  HANDLE hFind = INVALID_HANDLE_VALUE;
  char searchPath[MAX_PATH_LENGTH];

  snprintf(searchPath, MAX_PATH_LENGTH, "%s\\*", directory);
  hFind = FindFirstFile(searchPath, &findFileData);

  if (hFind == INVALID_HANDLE_VALUE) {
    printf("Invalid file handle. Error is %u\n", GetLastError());
    printf("Make sure the directory path is correct and you have the necessary "
           "permissions.\n");
    return;
  } else {
    printf("Listing files in directory: %s\n", directory);
    do {
      if (verbose == 1) {
        printf("Found: %s\n", findFileData.cFileName);
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          printf("Skipping directory: %s\n", findFileData.cFileName);
          continue;
        }
      }

      char filePath[MAX_PATH_LENGTH];
      snprintf(filePath, MAX_PATH_LENGTH, "%s\\%s", directory,
               findFileData.cFileName);

      analyze_pe_file(filePath, verbose);
    } while (FindNextFile(hFind, &findFileData) != 0);
    if (GetLastError() != ERROR_NO_MORE_FILES) {
      printf("FindNextFile error. Error is %u\n", GetLastError());
    }
    FindClose(hFind);
  }
}
