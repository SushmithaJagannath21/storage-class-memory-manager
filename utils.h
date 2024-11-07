#ifndef _UTILS_H_
#define _UTILS_H_

#include "system.h"

void create_crc_table(unsigned int *table);
unsigned int crc32(unsigned char *data, unsigned int length);
int create_file(const char *pathname);
size_t get_size(size_t * address);
void set_size(size_t * address, size_t size);
int validate_signature(uint8_t *address);
size_t string_length(const char* str);
void print(char * s);
void printmem(void * p);

#endif /* _AVL_H_ */
