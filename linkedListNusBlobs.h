#ifndef LINKED_LIST_NUS_BLOBS_H
#define LINKED_LIST_NUS_BLOBS_H

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

enum RegionType{
    UNDEFINED = 0x00,
    ENCRYPTED = 0x01,
    HASH = 0x02
};

typedef struct BlobRegion{
    uint64_t cnt_offset;
    uint64_t length;
    uint16_t content_id;
    uint32_t parent_id;
    enum RegionType type;
    struct BlobRegion * nextRegion;
}BlobRegion;

typedef struct BaseBlob{
    char blobPath[PATH_MAX];
    char destination[PATH_MAX];
    uint64_t length;
    uint16_t content_id;
    uint32_t parent_id;
    enum RegionType type;
    BlobRegion * firstRegion;
}BaseBlob;

typedef struct BaseBlobSet{
    struct BaseBlobSet * nextSet;
    BaseBlob * baseBlob;
}BaseBlobSet;

BaseBlob * llnb_new_BaseBlob(char * sourceFile, char* destination, uint64_t length);
void llnb_attach_region(
    BaseBlob * baseb, BlobRegion * baser, uint64_t cnt_offset,
    uint64_t length, uint16_t content_id, uint32_t parent_id, enum RegionType type
);
BaseBlob * llnb_add_BaseBlob_to_set(char * sourceFile, char * destination, uint64_t length, BaseBlobSet ** baseSet);

void llnb_print_region(BlobRegion * toPrint);
void llnb_print_BaseBlob(BaseBlob * baseBlob);
void llnb_print_BaseBlobSet(BaseBlobSet * baseBlobSet);

bool llnb_calculate_base_field(BaseBlob * blob);
bool llnb_calculate_base_fields(BaseBlobSet * bset);

void llnb_free_BaseBlob(BaseBlob ** baseBlob);
void llnb_free_BaseBlobSet(BaseBlobSet ** baseBlobSet);

#ifdef __cplusplus
}
#endif

#endif /* linkedList.h */
