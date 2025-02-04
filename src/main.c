#include "../include/pe_analyze.h"
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define OPTSTR "vsi:vsd:o:h"
#define USAGE_FMT "%s [-v] [-s] [-d directoryPath | -i inputfile] [-o JSON] [-h]\n"

extern char *optarg;
extern int opterr, optind;

typedef struct {
  int verbose;
  int directory;
  char *input;
  int silent;
  char *output;
} options_t;

void usage(char *progname, int opt);

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "\033[31mpextract: Missing Operand \n\033[0m");
    fprintf(stderr, "\033[31mTry 'pextract -h' for more information\033[0m");

    exit(EXIT_FAILURE);
  }

  int opt;
  options_t options = {0, 0, "", 0, ""};

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

    case 's':
      options.silent = 1;
      break;

    case 'h':
    default:
      usage(basename(argv[0]), opt);
      break;
    }

  if (options.directory == 1) {
    listFiles(options.verbose, options.input, options.silent, options.output);

    return 0;
  }

  analyze_pe_file(options.input, options.verbose, options.silent,
                  options.output);
  return 0;
}

void usage(char *progname, int opt) {
  fprintf(stderr, USAGE_FMT, progname);
  exit(EXIT_FAILURE);
}
