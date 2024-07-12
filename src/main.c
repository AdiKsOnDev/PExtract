#include "../include/pe_analyze.h"
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>

#define OPTSTR "vi:vd:o:h"
#define USAGE_FMT "%s [-v] [-d directoryPath] [-i inputfile] [-o outputfile] [-h]\n"

extern char *optarg;
extern int opterr, optind;

typedef struct {
  int     verbose;
  int     directory;
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
  options_t options = {0, 0, "", ""};

  opterr = 0;

  while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
    switch (opt) {
      case 'd':
        options.input = optarg;
        options.directory = 1;
        break;

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

  if (options.directory == 1) {
    listFiles(options.input);

    return 0;
  }

  analyze_pe_file(options.input, options.verbose);
  return 0;
}

void usage(char *progname, int opt) {
   fprintf(stderr, USAGE_FMT, progname);
   exit(EXIT_FAILURE);
}
