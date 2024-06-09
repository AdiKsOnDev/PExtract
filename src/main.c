#include "../include/pe_analyze.h"
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>

#define OPTSTR "vi:o:h"
#define USAGE_FMT "%s [-v] [ -i inputfile] [-o outputfile] [-h]\n"
#define CHECK_FOPEN_INPUT  "fopen(input, r)"
#define CHECK_FOPEN_OUTPUT "fopen(output, w)"

extern char *optarg;
extern int opterr, optind;

typedef struct {
  int     verbose;
  char   *input;
  char   *output;
} options_t;

void usage(char *progname, int opt);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "pextract: Missing Operand \n");
    fprintf(stderr, "Try 'pextract -h' for more information");

    exit(EXIT_FAILURE);
  }

  int opt;
  options_t options = {0, "", ""};

  opterr = 0;

  while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
    switch (opt) {
      case 'i':
        options.input = optarg;
        break;

      case 'o':
        options.output = optarg;
        break;

      case 'v':
        options.verbose = 1;
        break;

      case 'h':
      default:
        usage(basename(argv[0]), opt);
        break;
    }

  analyze_pe_file(options.input);
  return 0;
}

void usage(char *progname, int opt) {
   fprintf(stderr, USAGE_FMT, progname);
   exit(EXIT_FAILURE);
}
