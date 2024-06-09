#include "../include/pe_analyze.h"

int main() {
    char pe_path[] = "pefile.exe";
    analyze_pe_file(pe_path);
    return 0;
}
