#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define USAGE "Usage: %s -i INTERFACE -r IPv6/MASK [-n IPv6] [-m METRIC] [-t TAG]\n"

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL,
    *opt_network = NULL,
    *opt_next_hop = NULL,
    *opt_metric = NULL,
    *opt_tag = NULL;

  while ((opt = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    case 'r':
      opt_network = optarg;
      break;
    case 'n':
      opt_next_hop = optarg;
      break;
    case 'm':
      opt_metric = optarg;
      break;
    case 't':
      opt_tag = optarg;
      break;
    default:
      if (optopt == 'i' || optopt == 'r' || optopt == 'n' || optopt == 'm' || optopt == 't') {
        fprintf(stderr, "Missing argument for option `-%c'\n", optopt);
      } else {
        fprintf(stderr, "Unknown option `-%c'\n", optopt);
      }
      fprintf(stderr, USAGE, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL) {
    fprintf(stderr, "Missing required option `-i interface`\n");
    fprintf(stderr, USAGE, argv[0]);
    exit(EXIT_FAILURE);
  }
  if (opt_network == NULL) {
    fprintf(stderr, "Missing required option `-n IPv6/MASK`\n");
    fprintf(stderr, USAGE, argv[0]);
    exit(EXIT_FAILURE);
  }
  if (opt_next_hop == NULL) {
    opt_next_hop = "::";
  }
  if (opt_metric == NULL) {
    opt_metric = "1";
  }
  if (opt_tag == NULL) {
    opt_tag = "0";
  }

  //TODO:

  return 0;
}
