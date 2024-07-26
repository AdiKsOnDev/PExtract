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
