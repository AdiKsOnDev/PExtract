#ifndef PE_ANALYZE
#define PE_ANALYZE

#include "disassembly.h"
#include "extract_info.h"

void analyze_pe_file(char *pe_path, int verbose, int silent, char *output);
#endif // !PE_ANALYZE
