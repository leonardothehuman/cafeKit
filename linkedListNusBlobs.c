#include "linkedListNusBlobs.h"
#include "sglib.h"

BaseBlob * llnb_add_BaseBlob_to_set(char * sourceFile, char * destination, uint64_t length, BaseBlobSet ** baseSet){
    if(*baseSet == NULL){
        *baseSet = calloc(1, sizeof(BaseBlobSet));
        (*baseSet)->baseBlob = llnb_new_BaseBlob(sourceFile, destination, length);
        (*baseSet)->nextSet = NULL;
        return (*baseSet)->baseBlob;
    }else{
        BaseBlobSet * currentBlobSet = *baseSet;
        while (1){
            if(strcmp(currentBlobSet->baseBlob->blobPath, sourceFile) == 0) {
               return currentBlobSet->baseBlob;
            }
            // printf("NOT EQUAL %s:%s", currentBlobSet->baseBlob->blobPath, sourceFile);
            if(currentBlobSet->nextSet == NULL) break;
            currentBlobSet = currentBlobSet->nextSet;
        }
        llnb_add_BaseBlob_to_set(sourceFile, destination, length, &(currentBlobSet->nextSet));
    }
}

BaseBlob * llnb_new_BaseBlob(char * sourceFile, char * destination, uint64_t length){
    BaseBlob * toReturn = calloc(1, sizeof(BaseBlob));
    strcpy(toReturn->blobPath, sourceFile);
    strcpy(toReturn->destination, destination);
    toReturn->length = length;
    toReturn->firstRegion = NULL;
    toReturn->content_id = 0;
    toReturn->parent_id = 0;
    toReturn->type = UNDEFINED;
    return toReturn;
}

void llnb_attach_region(
    BaseBlob * baseb, BlobRegion * baser, uint64_t cnt_offset,
    uint64_t length, uint16_t content_id, uint32_t parent_id, enum RegionType type
){
    BlobRegion * nr = calloc(1, sizeof(BlobRegion));
    nr->cnt_offset = cnt_offset;
    nr->length = length;
    nr->content_id = content_id;
    nr->parent_id = parent_id;
    nr->type = type;
    nr->nextRegion = NULL;
    if(baseb != NULL){
        if(baseb->firstRegion == NULL){
            baseb->firstRegion = nr;
        }else{
            baser = baseb->firstRegion;
        }
    }
    if(baser != NULL){
        //This is not the most efficient way to do it, but is fast enouth for our use
        while(baser->nextRegion != NULL){
            baser = baser->nextRegion;
        }
        baser->nextRegion = nr;
    }
}

void llnb_print_region(BlobRegion * toPrint){
    printf(
        "Offset: %" PRIx64 ", Length: %" PRIx64 ", ID: %" PRIx16 ", BID: %" PRIx32 ", Type: %" PRIx8 "\n",
        toPrint->cnt_offset, toPrint->length, toPrint->content_id, toPrint->parent_id, toPrint->type
    );
}

void llnb_print_BaseBlob(BaseBlob * baseBlob){
    BlobRegion * c = baseBlob->firstRegion;
    printf(
        "File: %s, Size: %" PRIx64 ", ID: %" PRIx16", BID: %" PRIx32 ",Type: %"PRIx8", Destination: %s\n",
        baseBlob->blobPath, baseBlob->length, baseBlob->content_id, baseBlob->parent_id, baseBlob->type, baseBlob->destination
    );
    while(1){
        printf("\t");
        llnb_print_region(c);
        if(c->nextRegion == NULL){
            break;
        }
        c = c->nextRegion;
    }
}

void llnb_print_BaseBlobSet(BaseBlobSet * baseBlobSet){
    BaseBlobSet * c = baseBlobSet;
    while(1){
        llnb_print_BaseBlob(c->baseBlob);
        if(c->nextSet == NULL){
            break;
        }
        c = c->nextSet;
    };
}

bool llnb_calculate_base_field(BaseBlob * blob){
    bool r = true;
    BlobRegion * c = blob->firstRegion;
    uint16_t content_id = blob->firstRegion->content_id;
    uint16_t parent_id = blob->firstRegion->parent_id;
    enum RegionType type = blob->firstRegion->type;
    while(1){
        if(content_id != c->content_id) r = false;
        if(parent_id != c->parent_id) r = false;
        if(type != c->type) r = false;
        if(c->nextRegion == NULL){
            break;
        }
        c=c->nextRegion;
    }
    blob->content_id = content_id;
    blob->parent_id = parent_id;
    blob->type = type;
    if(r == false){
        blob->content_id = 0;
        blob->type = UNDEFINED;
    }
    return r;
}

bool llnb_calculate_base_fields(BaseBlobSet * bset){
    bool r = true;
    while(1){
        if(llnb_calculate_base_field(bset->baseBlob) == false) r = false;
        if(bset->nextSet == NULL){
            break;
        }
        bset = bset->nextSet;
    }
    return r;
}

void llnb_free_BaseBlob(BaseBlob ** baseBlob){
    BlobRegion * c = (*baseBlob)->firstRegion;
    BlobRegion * n = c->nextRegion;
    // printf(
    //     "File: %s, Size: %" PRIx64 ", ID: %" PRIx16", Type: %"PRIx8", Destination: %s\n",
    //     (*baseBlob)->blobPath, (*baseBlob)->length, (*baseBlob)->content_id, (*baseBlob)->type, (*baseBlob)->destination
    // );
    while(1){
        // printf(
        //     "Offset: %" PRIx64 ", Length: %" PRIx64 ", ID: %" PRIx16 ", Type: %" PRIx8 "\n",
        //     c->cnt_offset, c->length, c->content_id, c->type
        // );
        free(c);
        if(n == NULL){
            break;
        }
        c = n;
        n = c->nextRegion;
    }
    free(*baseBlob);
}

void llnb_free_BaseBlobSet(BaseBlobSet ** baseBlobSet){
    BaseBlobSet * c = *baseBlobSet;
    BaseBlobSet * n = c->nextSet;
    while(1){
        llnb_free_BaseBlob(&(c->baseBlob));
        free(c);
        if(n == NULL){
            break;
        }
        c = n;
        n = c->nextSet;
    };
    *baseBlobSet = NULL;
}