/**
 * Tony Givargis
 * Copyright (C), 2023
 * University of California, Irvine
 *
 * CS 238P - Operating Systems
 * scm.c
 */
#define _GNU_SOURCE
#define VIRT_ADDRESS 0x600000000000

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "scm.h"
#include "utils.h"

/**
 * Needs:
 *   fstat()
 *   S_ISREG()
 *   open()
 *   close()
 *   sbrk()
 *   mmap()
 *   munmap()
 *   msync()
 */

/* research the above Needed API and design accordingly */

struct scm
{
    int fd;
    size_t length, size, metadata; /* total file size, currently occupied size, metadata size in bytes*/
    char *addr, *size_ptr, *base;
};

int create_file(const char *pathname)
{
    FILE *fd;
    char cmd[200]; /* Make sure it's large enough to hold the entire command */
    strcpy(cmd, "dd if=/dev/zero bs=4096 count=10000 of=");
    strcat(cmd, pathname);
    fd = popen(cmd, "w");
    if (!fd)
    {
        TRACE("Failed pipe open execution!!");
        return -1;
    }
    pclose(fd);
    return 0;
}

void print(char *s)
{
    FILE *f;
    f = fopen("output.txt", "a");
    if (f == NULL)
    {
        TRACE("Failed to open file");
        return;
    }
    fprintf(f, "%s\n", s);
    fclose(f);
}

void printmem(void *p)
{
    FILE *f;
    f = fopen("output.txt", "a");
    if (f == NULL)
    {
        TRACE("Failed to open file");
        return;
    }
    fprintf(f, "%p\n", p);
    fclose(f);
}

size_t get_size(size_t *address)
{
    size_t size;
    char buffer[200];
    size = *address;
    snprintf(buffer, sizeof(buffer), "%lu", size);
    print("Getting size =");
    print(buffer);
    print("At address =");
    printmem((void *)address);
    print("------------------------------------------");
    return size;
}

/* put size into memory on 1st time init or whenever size change has occured*/
void set_size(size_t *address, size_t size)
{
    char buffer[200];
    *address = size;
    snprintf(buffer, sizeof(buffer), "%lu", size);
    print("Storing size =");
    print(buffer);
    print("At address =");
    printmem((void *)address);
    print("------------------------------------------");
    return;
}

int truncate_and_createFile(int truncate, const char *pathname)
{
    if (truncate)
    { /* Delete old output file*/
        if (remove("output.txt") == 0)
        {
            print("The file has been deleted");
        }
        else
        {
            print("Deletion failed");
        }

        if (create_file(pathname) < 0)
        {
            TRACE("Failed file creation!!");
            return 0;
        }
    }
    return 1;
}

struct scm *structMapping(const char *pathname)
{
    int fd_;
    char *curr_brk;
    struct scm *scm_ptr;
    struct stat finfo;
    /*size_t file_length;*/

    if (!(scm_ptr = (struct scm *)malloc(sizeof(struct scm))))
    {
        TRACE("Failed malloc for SCM struct!!");
        return NULL;
    }
    memset(scm_ptr, 0, sizeof(struct scm));
    /* Open file*/
    fd_ = open(pathname, O_RDWR);
    if (fd_ < 0)
    {
        TRACE("Failed file opening!!");
        FREE(scm_ptr);
        return NULL;
    }
    scm_ptr->fd = fd_;
    /* Get file statistics*/
    if (fstat(fd_, &finfo) < 0)
    {
        TRACE("Failed execution fstat!!");
        FREE(scm_ptr);
        return NULL;
    }
    /* Checking if the file is regular file*/
    if (S_ISREG(finfo.st_mode) == 0)
    {
        TRACE("Not a regular file!");
        FREE(scm_ptr);
        return NULL;
    }

    /* Sanity check for virtual memory start address*/
    curr_brk = sbrk(0);
    if (curr_brk >= (char *)VIRT_ADDRESS)
    {
        TRACE("Virtual memory start address is below break line");
        FREE(scm_ptr);
        return NULL;
    }
    scm_ptr->length = (size_t)finfo.st_size;

    /*scm_ptr->size = 0;*/
    return scm_ptr;
}

int validate_signature(uint8_t *address)
{
    uint8_t actual_signature[3] = {0xAA, 0xBB, 0xCC};
    uint8_t read_signature[3];
    int i;

    printf("Signature values: ");

    /* Read the signature and print the values */
    for (i = 0; i < 3; i++)
    {
        read_signature[i] = *address++;
        printf("%d ", read_signature[i]);
    }
    printf("\n");

    /*Directly compare the read signature with the expected signature*/
    return memcmp(actual_signature, read_signature, 3) == 0 ? 0 : -1;
}

struct scm *scm_open(const char *pathname, int truncate)
{
    void *map_ptr;
    uint8_t signature[3] = {0xAA, 0xBB, 0xCC}; /* signature to encode in the start of memory*/
    uint8_t *uint8_t_ptr;
    size_t *size_t_ptr;
    struct scm *scm_ptr;

    /*If truncate logic is passed*/
    int filecreation = truncate_and_createFile(truncate, pathname);
    if (filecreation == 0)
    {
        TRACE("File not created");
        return NULL;
    }

    scm_ptr = structMapping(pathname);
    if (!scm_ptr)
    {
        TRACE("SCM pointer is not created");
        return NULL;
    }

    /* mmap file and process virtual memory*/
    map_ptr = (void *)mmap((void *)VIRT_ADDRESS, scm_ptr->length, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED, scm_ptr->fd, 0);
    if ((map_ptr == MAP_FAILED) || (map_ptr != (void *)VIRT_ADDRESS))
    {
        TRACE("Failed execution mmap!!");
        close(scm_ptr->fd);
        FREE(scm_ptr);
        return NULL;
    }
    print("SCM Opening");
    /* If truncate, initlize scm attributes as it is a new file */
    if (truncate)
    {
        print("Truncating existing file");
        scm_ptr->addr = (char *)map_ptr;
        scm_ptr->base = (char *)map_ptr;
        scm_ptr->size = 0;
        /*scm_ptr->fd = fd;*/
        /*scm_ptr->length = file_length;*/
        scm_ptr->metadata = 0;

        /* encode signature(3 bytes) to location and incement pointer */
        /* typecast to uint8_t to get byte wise access to memory */
        uint8_t_ptr = (uint8_t *)scm_ptr->base;
        memcpy(uint8_t_ptr, signature, 3);
        uint8_t_ptr += 3;
        scm_ptr->base = (char *)uint8_t_ptr;
        scm_ptr->metadata += 3 * (sizeof(uint8_t));

        /* encode size to specified location and increment pointer*/
        size_t_ptr = (size_t *)scm_ptr->base;
        scm_ptr->size_ptr = (char *)size_t_ptr;
        set_size(size_t_ptr, scm_ptr->size);
        size_t_ptr += 1;
        scm_ptr->base = (char *)size_t_ptr;
        scm_ptr->metadata += 1 * (sizeof(size_t));
        return scm_ptr;
    } /* Else validate signature, load size from file, init everything else */
    else
    {
        print("Loading from file");
        scm_ptr->addr = (char *)map_ptr;
        scm_ptr->base = (char *)map_ptr;
        scm_ptr->metadata = 0;

        /* validate signature*/
        uint8_t_ptr = (uint8_t *)scm_ptr->base;
        if (-1 == validate_signature(uint8_t_ptr))
        {
            TRACE("Garbage Values in File");
            FREE(scm_ptr);
            return NULL;
        }
        uint8_t_ptr += 3;
        scm_ptr->base = (char *)uint8_t_ptr;
        scm_ptr->metadata += 3 * (sizeof(uint8_t));

        /* get size from memory*/
        size_t_ptr = (size_t *)scm_ptr->base;
        scm_ptr->size_ptr = (char *)size_t_ptr;
        scm_ptr->size = get_size(size_t_ptr);
        size_t_ptr += 1;
        scm_ptr->base = (char *)size_t_ptr;
        scm_ptr->metadata += 1 * (sizeof(size_t));
        return scm_ptr;
    }
}

void *scm_malloc(struct scm *scm, size_t n)
{
    size_t size;
    size_t *size_t_ptr;
    print("Malloc occured");
    size = scm->size;
    scm->size += n;
    size_t_ptr = (size_t *)scm->size_ptr;
    set_size(size_t_ptr, scm->size);
    return (void *)(scm->base + size);
}

void *scm_mbase(struct scm *scm)
{
    return (void *)scm->base;
}

size_t scm_capacity(const struct scm *scm)
{
    return scm->length;
}

size_t scm_utilized(const struct scm *scm)
{
    return scm->size;
}

void scm_close(struct scm *scm)
{
    print("SCM Closing");
    /* performs msync and munmap*/
    if (close(scm->fd) < 0)
    {
        TRACE("Failed closing file!!");
        FREE(scm);
        return;
    }
    if (msync((void *)scm->addr, scm->length, MS_SYNC | MS_INVALIDATE) < 0)
    {
        TRACE("Failed msync execution!!");
        FREE(scm);
        return;
    }
    if (munmap((void *)scm->addr, scm->length) < 0)
    {
        TRACE("Failed munmap execution!!");
        FREE(scm);
        return;
    }
    FREE(scm);
}
size_t string_length(const char *str)
{
    size_t length = 0;

    /* Iterate through the string using a pointer */
    while (*str != '\0')
    {
        length++;
        str++; /* Move the pointer to the next character */
    }
    return length;
}

char *scm_strdup(struct scm *scm, const char *s)
{
    size_t length;
    char *new_string;
    length = string_length(s);
    new_string = (char *)scm_malloc(scm, length);
    memcpy(new_string, s, length);
    return new_string;
}

void scm_free(struct scm *scm, void *p)
{
    if ((char *)p < (char *)scm->addr || (char *)p > (char *)scm->addr + scm->length)
    {
        perror("out of valid range");
    }
    *(short *)((char *)p - sizeof(short) - sizeof(size_t)) = 0;
}
