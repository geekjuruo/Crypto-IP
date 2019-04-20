// Package: Crypto-PAn 1.0
// File: sample.cpp
// Last Update: April 17, 2002
// Author: Jinliang Fan

#include <stdlib.h>
#include <stdio.h>
#include "panonymizer.h"

int main(int argc, char * argv[]) {
    // Provide your own 256-bit key here
    unsigned char my_key[32] = 
    {21,34,23,141,51,164,207,128,19,10,91,22,73,144,125,16,
     216,152,143,131,121,121,101,39,98,87,76,45,42,132,34,2};

    FILE * f;
    unsigned int raw_addr, anonymized_addr;

    // Create an instance of PAnonymizer with the key
    PAnonymizer my_anonymizer(my_key);

    float packet_time;
    unsigned int packet_size, packet_addr1, packet_addr2, packet_addr3, packet_addr4;

    if (argc != 2) {
      fprintf(stderr, "usage: sample raw-trace-file\n");
      exit(-1);
    }
    
    if ((f = fopen(argv[1],"r")) == NULL) {
      fprintf(stderr,"Cannot open file %s\n", argv[1]);
      exit(-2);
    }
       
    //readin and handle each line of the input file
    while  (fscanf(f, "%u.%u.%u.%u", &packet_addr1, &packet_addr2, &packet_addr3, &packet_addr4) != EOF) {
      // fscanf(f, "%u", &packet_size);
      // fscanf(f, "%u.%u.%u.%u", &packet_addr1, &packet_addr2, &packet_addr3, &packet_addr4);

      //convert the raw IP from a.b.c.d format into unsigned int format.
      raw_addr = (packet_addr1 << 24) + (packet_addr2 << 16) + (packet_addr3 << 8) + packet_addr4;

      //Anonymize the raw IP
      anonymized_addr = my_anonymizer.anonymize(raw_addr);

      //convert the anonymized IP from unsigned int format to a.b.c.d format
      packet_addr1 = anonymized_addr >> 24;
      packet_addr2 = (anonymized_addr << 8) >> 24;
      packet_addr3 = (anonymized_addr << 16) >> 24;
      packet_addr4 = (anonymized_addr << 24) >> 24;

      //output the sanitized trace
      printf("%6f\t%u\t%u.%u.%u.%u\n",  packet_time, packet_size, packet_addr1, packet_addr2, packet_addr3, packet_addr4 );
    }

}
