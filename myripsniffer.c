#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void usage(char *argv[]) {
  fprintf(stderr, "Usage: %s -i interface\n", argv[0]);
}

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL;

  while ((opt = getopt(argc, argv, "i:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    default:
      usage(argv);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL) {
    usage(argv);
    exit(EXIT_FAILURE);
  }

  //TODO:

  return 0;
}
