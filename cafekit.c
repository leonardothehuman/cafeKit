/*
  cafeKit - Decrypt Wii U NUS content to save space on compression, then 
  reencrypt the content with 1:1 output from the original nus package

  Copyright © 2013-2015 crediar <https://code.google.com/p/cdecrypt/>
  Copyright © 2020-2021 VitaSmith <https://github.com/VitaSmith/cdecrypt>
  Copyright © 2022-2023 leonardo the human <https://github.com/leonardothehuman/cafeKit>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "utf8.h"
#include "util.h"
#include "aes.h"
#include "sha1.h"
#include "linkedListNusBlobs.h"
#include "cafeKit_private.h"

#define MAX_ENTRIES     90000
#define MAX_LEVELS      16
#define FST_MAGIC       0x46535400              // 'FST\0'
// We use part of the root cert name used by TMD/TIK to identify them
#define TMD_MAGIC       0x4350303030303030ULL   // 'CP000000'
#define TIK_MAGIC       0x5853303030303030ULL   // 'XS000000'
#define T_MAGIC_OFFSET  0x0150
#define HASH_BLOCK_SIZE 0xFC00
#define HASHES_SIZE     0x0400

static const uint8_t WiiUCommonDevKey[16] =
    { 0x2F, 0x5C, 0x1B, 0x29, 0x44, 0xE7, 0xFD, 0x6F, 0xC3, 0x97, 0x96, 0x4B, 0x05, 0x76, 0x91, 0xFA };
static const uint8_t WiiUCommonKey[16] =
    { 0xD7, 0xB0, 0x04, 0x02, 0x65, 0x9B, 0xA2, 0xAB, 0xD2, 0xCB, 0x0D, 0xB2, 0x7F, 0xA2, 0xB6, 0x56 };

aes_context     ctx;
aes_context     ectx;
uint8_t         title_id[16];
uint8_t         title_key[16];
uint64_t        h0_count = 0;
uint64_t        h0_fail  = 0;

#pragma pack(1)

char destination_directory[PATH_MAX];
const char* pattern_path[] = { "%s%c%08x.app", "%s%c%08X.app", "%s%c%08x", "%s%c%08X" };
const char* pattern_h3[] = { "%s%c%08x.h3", "%s%c%08X.h3" };
char * input_directory;

enum ApplicationMode{
    ENCRYPT = 0x00,
    DECRYPT = 0x01
};
enum ApplicationMode application_mode;

enum ContentType
{
    CONTENT_REQUIRED = (1 << 0),    // Not sure
    CONTENT_SHARED   = (1 << 15),
    CONTENT_OPTIONAL = (1 << 14),
};

typedef struct
{
    uint16_t IndexOffset;           //  0  0x204
    uint16_t CommandCount;          //  2  0x206
    uint8_t  SHA2[32];              //  12 0x208
} ContentInfo;

typedef struct
{
    uint32_t ID;                    //  0  0xB04
    uint16_t Index;                 //  4  0xB08
    uint16_t Type;                  //  6  0xB0A
    uint64_t Size;                  //  8  0xB0C
    uint8_t  SHA2[32];              //  16 0xB14
} Content;

typedef struct
{
    uint32_t SignatureType;         // 0x000
    uint8_t  Signature[0x100];      // 0x004

    uint8_t  Padding0[0x3C];        // 0x104
    uint8_t  Issuer[0x40];          // 0x140

    uint8_t  Version;               // 0x180
    uint8_t  CACRLVersion;          // 0x181
    uint8_t  SignerCRLVersion;      // 0x182
    uint8_t  Padding1;              // 0x183

    uint64_t SystemVersion;         // 0x184
    uint64_t TitleID;               // 0x18C
    uint32_t TitleType;             // 0x194
    uint16_t GroupID;               // 0x198
    uint8_t  Reserved[62];          // 0x19A
    uint32_t AccessRights;          // 0x1D8
    uint16_t TitleVersion;          // 0x1DC
    uint16_t ContentCount;          // 0x1DE
    uint16_t BootIndex;             // 0x1E0
    uint8_t  Padding3[2];           // 0x1E2
    uint8_t  SHA2[32];              // 0x1E4

    ContentInfo ContentInfos[64];

    Content  Contents[];            // 0x1E4

} TitleMetaData;

struct FSTInfo
{
    uint32_t Unknown;
    uint32_t Size;
    uint32_t UnknownB;
    uint32_t UnknownC[6];
};

struct FST
{
    uint32_t MagicBytes;
    uint32_t Unknown;
    uint32_t EntryCount;

    uint32_t UnknownB[5];

    struct FSTInfo FSTInfos[];
};

struct FEntry
{
    union
    {
        struct
        {
            uint32_t Type : 8;
            uint32_t NameOffset : 24;
        };
        uint32_t TypeName;
    };
    union
    {
        struct      // File Entry
        {
            uint32_t FileOffset;
            uint32_t FileLength;
        };
        struct       // Dir Entry
        {
            uint32_t ParentOffset;
            uint32_t NextOffset;
        };
        uint32_t entry[2];
    };
    uint16_t Flags;
    uint16_t ContentID;
};

int dir_empty(const char *path){ //checks if the directory is empty
	struct dirent *ent;
	int ret = 1;

	DIR *d = opendir(path);
	if (!d) {
		fprintf(stderr, "%s: ", path);
		perror("");
		return -1;
	}

	while ((ent = readdir(d))) {
		if (!strcmp(ent->d_name, ".") || !(strcmp(ent->d_name, "..")))
			continue;
		ret = 0;
		break;
	}

	closedir(d);
	return ret;
}

static bool file_dump(const char* path, void* buf, size_t len)
{
    assert(buf != NULL);
    assert(len != 0);

    FILE* dst = fopen_utf8(path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not dump file '%s'\n", path);
        return false;
    }

    bool r = (fwrite(buf, 1, len, dst) == len);
    if (!r)
        fprintf(stderr, "ERROR: Failed to dump file '%s'\n", path);

    fclose(dst);
    return r;
}

static __inline char ascii(char s)
{
    if (s < 0x20) return '.';
    if (s > 0x7E) return '.';
    return s;
}

static void hexdump(uint8_t* buf, size_t len)
{
    size_t i, off;
    for (off = 0; off < len; off += 16) {
        printf("%08x  ", (uint32_t)off);
        for (i = 0; i < 16; i++)
            if ((i + off) >= len)
                printf("   ");
            else
                printf("%02x ", buf[off + i]);

        printf(" ");
        for (i = 0; i < 16; i++) {
            if ((i + off) >= len)
                printf(" ");
            else
                printf("%c", ascii(buf[off + i]));
        }
        printf("\n");
    }
}

int endsWith(const char *str, const char *suffix){
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix > lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

#define BLOCK_SIZE  0x10000
static bool decrypt_entire_file_hash(FILE* src, uint64_t size, const char* destination, uint16_t content_id, const char* hashDestination){
    bool r = false; //To return error or success
    uint8_t *enc = malloc(BLOCK_SIZE); //Buffer to store encrypted data
    uint8_t *dec = malloc(BLOCK_SIZE); //Buffer to store decrypted data
    assert(enc != NULL);
    assert(dec != NULL);
    uint8_t iv[16]; //Initialization vector
    uint8_t hash[SHA_DIGEST_LENGTH]; //Stores the hash that was calculated from the decrypted readed block
    uint8_t h0[SHA_DIGEST_LENGTH];//Hash readed from disk
    uint8_t hashes[HASHES_SIZE]; //Stores hashes addresses readed from file

    uint64_t written = 0;//Counts how many bytes has been written
    uint64_t block_number = 0;

    FILE* dst = fopen_utf8(destination, "wb");//Creates the output file
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", destination);
        goto out;
    }
    FILE* hdst = fopen_utf8(hashDestination, "wb");//Creates the output file
    if (hdst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", hashDestination);
        goto out;
    }

    uint64_t initialSize = size;
    char progress[20] = "";
    uint16_t progress_length = 0;
    uint64_t percentage = 0;
    fseek64(src, 0, SEEK_SET);
    while (size > 0) {
        if(block_number == 0){
            progress_length = strlen(progress);
            for(uint8_t i = 0; i < progress_length; i++){
                printf("\b \b");
            }
            percentage = (100 * (initialSize - size)) / initialSize;
            sprintf(progress, "%" PRIu64 " %%", percentage);
            printf("%s", progress);
        }
        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes to '%s'\n", BLOCK_SIZE, destination);
            goto out;
        }
        memset(iv, 0, sizeof(iv));
        iv[1] = (uint8_t)content_id;
        aes_crypt_cbc(&ctx, AES_DECRYPT, HASHES_SIZE, iv, enc, (uint8_t*)hashes);
        memcpy(h0, hashes + 0x14 * block_number, SHA_DIGEST_LENGTH);
        memcpy(iv, hashes + 0x14 * block_number, sizeof(iv));
        if (block_number == 0)
            iv[1] ^= content_id;

        aes_crypt_cbc(&ctx, AES_DECRYPT, HASH_BLOCK_SIZE, iv, enc + HASHES_SIZE, dec);
        sha1(dec, HASH_BLOCK_SIZE, hash);

        if (block_number == 0)
            hash[1] ^= content_id;
        h0_count++;
        if (memcmp(hash, h0, SHA_DIGEST_LENGTH) != 0) {
            h0_fail++;
            hexdump(hash, SHA_DIGEST_LENGTH);
            hexdump(h0, SHA_DIGEST_LENGTH);
            hexdump(hashes, 0x100);
            hexdump(dec, 0x100);
            fprintf(stderr, "ERROR: Could not verify H0 hash\n");
            goto out;
        }

        size -= fwrite(hashes, sizeof(char), HASHES_SIZE, hdst);
        size -= fwrite(dec, sizeof(char), HASH_BLOCK_SIZE, dst);

        block_number++;
        if (block_number >= 16)
            block_number = 0;
    }
    progress_length = strlen(progress);
    for(uint8_t i = 0; i < progress_length; i++){
        printf("\b \b");
    }
    printf("100 %%\n");
    r = true;
out:
    if (dst != NULL)
        fclose(dst);
    if (hdst != NULL)
        fclose(hdst);
    free(enc);
    free(dec);
    return r;
}

static bool encrypt_entire_file_hash(FILE* src, FILE* hsrc, uint64_t size, const char* destination, uint16_t content_id){
    bool r = false; //To return error or success
    uint8_t *enc = malloc(BLOCK_SIZE); //Buffer to store encrypted data
    uint8_t *dec = malloc(BLOCK_SIZE); //Buffer to store decrypted data
    assert(enc != NULL);
    assert(dec != NULL);
    uint8_t iv[16]; //Initialization vector
    uint8_t hash[SHA_DIGEST_LENGTH]; //Stores the hash that was calculated from the decrypted readed block
    uint8_t h0[SHA_DIGEST_LENGTH];//Hash readed from disk
    uint8_t hashes[HASHES_SIZE]; //Stores hashes addresses readed from file

    uint64_t written = 0;//Counts how many bytes has been written
    uint64_t block_number = 0;

    FILE* dst = fopen_utf8(destination, "wb");//Creates the output file
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", destination);
        goto out;
    }

    uint64_t initialSize = size;
    char progress[20] = "";
    uint16_t progress_length = 0;
    uint64_t percentage = 0;
    fseek64(src, 0, SEEK_SET);
    while (size > 0) {
        if(block_number == 0){
            progress_length = strlen(progress);
            for(uint8_t i = 0; i < progress_length; i++){
                printf("\b \b");
            }
            percentage = (100 * (initialSize - size)) / initialSize;
            sprintf(progress, "%" PRIu64 " %%", percentage);
            printf("%s", progress);
        }
        if (fread(enc, sizeof(char), HASHES_SIZE, hsrc) != HASHES_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes to '%s'\n", HASHES_SIZE, destination);
            goto out;
        }
        if (fread(enc + HASHES_SIZE, sizeof(char), HASH_BLOCK_SIZE, src) != HASH_BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes to '%s'\n", HASH_BLOCK_SIZE, destination);
            goto out;
        }
        
        memset(iv, 0, sizeof(iv));
        iv[1] = (uint8_t)content_id;
        aes_crypt_cbc(&ectx, AES_ENCRYPT, HASHES_SIZE, iv, enc, dec);
        memcpy(h0, enc + 0x14 * block_number, SHA_DIGEST_LENGTH);
        memcpy(iv, enc + 0x14 * block_number, sizeof(iv));
        if (block_number == 0)
            iv[1] ^= content_id;

        aes_crypt_cbc(&ectx, AES_ENCRYPT, HASH_BLOCK_SIZE, iv, enc + HASHES_SIZE, dec + HASHES_SIZE);
        sha1(enc + HASHES_SIZE, HASH_BLOCK_SIZE, hash);

        if (block_number == 0)
            hash[1] ^= content_id;
        h0_count++;
        if (memcmp(hash, h0, SHA_DIGEST_LENGTH) != 0) {
            h0_fail++;
            hexdump(hash, SHA_DIGEST_LENGTH);
            hexdump(h0, SHA_DIGEST_LENGTH);
            hexdump(enc, 0x100);
            hexdump(enc + HASHES_SIZE, 0x100);
            fprintf(stderr, "ERROR: Could not verify H0 hash\n");
            goto out;
        }

        fwrite(dec, sizeof(char), HASHES_SIZE, dst);
        size -= fwrite(dec + HASHES_SIZE, sizeof(char), HASH_BLOCK_SIZE, dst);

        block_number++;
        if (block_number >= 16)
            block_number = 0;
    }
    progress_length = strlen(progress);
    for(uint8_t i = 0; i < progress_length; i++){
        printf("\b \b");
    }
    printf("100 %%\n");
    r = true;
out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
    return r;
}
static bool extract_file_hash(FILE* src, uint64_t part_data_offset, uint64_t file_offset,
                              uint64_t size, const char* path, uint16_t content_id)
{
    bool r = false; //To return error or success
    uint8_t *enc = malloc(BLOCK_SIZE); //Buffer to store encrypted data
    uint8_t *dec = malloc(BLOCK_SIZE); //Buffer to store decrypted data
    assert(enc != NULL);
    assert(dec != NULL);
    uint8_t iv[16]; //Initialization vector
    uint8_t hash[SHA_DIGEST_LENGTH]; //Stores the hash that was calculated from the decrypted readed block
    uint8_t h0[SHA_DIGEST_LENGTH];//Hash readed from disk
    uint8_t hashes[HASHES_SIZE]; //Stores hashes addresses readed from file

    uint64_t written = 0;//Counts how many bytes has been written
    uint64_t write_size = HASH_BLOCK_SIZE; //How many bytes will be written in each iteraction
    uint64_t block_number = (file_offset / HASH_BLOCK_SIZE) & 0x0F;//The current block number

    FILE* dst = fopen_utf8(path, "wb");//Creates the output file
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", path);
        goto out;
    }

    uint64_t roffset = file_offset / HASH_BLOCK_SIZE * BLOCK_SIZE; //Where the file really begins, with hash offset
    uint64_t soffset = file_offset - (file_offset / HASH_BLOCK_SIZE * HASH_BLOCK_SIZE);
    //Seems like the first decrypted block have an offset of the real beginning of the file

    if (soffset + size > write_size) //On the first block write_size may be different
        write_size = write_size - soffset; //The write size of the first blockshould be subtracted from the initial additional offset

    fseek64(src, part_data_offset + roffset, SEEK_SET);
    while (size > 0) {
        if (write_size > size) //The last block is smaller
            write_size = size;

        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes from '%s'\n", BLOCK_SIZE, path);
            goto out;
        }

        memset(iv, 0, sizeof(iv));
        iv[1] = (uint8_t)content_id;
        aes_crypt_cbc(&ctx, AES_DECRYPT, HASHES_SIZE, iv, enc, (uint8_t*)hashes);

        memcpy(h0, hashes + 0x14 * block_number, SHA_DIGEST_LENGTH);

        memcpy(iv, hashes + 0x14 * block_number, sizeof(iv));
        if (block_number == 0)
            iv[1] ^= content_id;
        aes_crypt_cbc(&ctx, AES_DECRYPT, HASH_BLOCK_SIZE, iv, enc + HASHES_SIZE, dec);

        sha1(dec, HASH_BLOCK_SIZE, hash);

        if (block_number == 0)
            hash[1] ^= content_id;
        h0_count++;
        if (memcmp(hash, h0, SHA_DIGEST_LENGTH) != 0) {
            h0_fail++;
            hexdump(hash, SHA_DIGEST_LENGTH);
            hexdump(hashes, 0x100);
            hexdump(dec, 0x100);
            fprintf(stderr, "ERROR: Could not verify H0 hash\n");
            goto out;
        }

        size -= fwrite(dec + soffset, sizeof(char), (size_t)write_size, dst);

        written += write_size;
        block_number++;
        if (block_number >= 16)
            block_number = 0;

        if (soffset) {
            write_size = HASH_BLOCK_SIZE;
            soffset = 0;
        }
    }
    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
}
#undef BLOCK_SIZE

#define BLOCK_SIZE  0x8000
static bool decrypt_entire_file(FILE* src, uint64_t size, const char* destination, uint16_t content_id){
    bool r = false;
    uint8_t* enc = malloc(BLOCK_SIZE);
    uint8_t* dec = malloc(BLOCK_SIZE);
    assert(enc != NULL);
    assert(dec != NULL);
    uint64_t written = 0;
    uint64_t block_number = 0;

    FILE* dst = fopen_utf8(destination, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", destination);
        goto out;
    }
    
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_id;

    uint64_t initialSize = size;
    char progress[20] = "";
    uint16_t progress_length = 0;
    uint64_t percentage = 0;
    fseek64(src, 0, SEEK_SET);
    while (size > 0) {
        if(block_number == 0){
            progress_length = strlen(progress);
            for(uint8_t i = 0; i < progress_length; i++){
                printf("\b \b");
            }
            percentage = (100 * (initialSize - size)) / initialSize;
            sprintf(progress, "%" PRIu64 " %%", percentage);
            printf("%s", progress);
        }
        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes to '%s'\n", BLOCK_SIZE, destination);
            goto out;
        }

        aes_crypt_cbc(&ctx, AES_DECRYPT, BLOCK_SIZE, iv, (const uint8_t*)(enc), (uint8_t*)dec);

        size -= fwrite(dec, sizeof(char), BLOCK_SIZE, dst);

        block_number++;
        if (block_number >= 16)
            block_number = 0;
    }
    progress_length = strlen(progress);
    for(uint8_t i = 0; i < progress_length; i++){
        printf("\b \b");
    }
    printf("100 %%\n");
    r = true;
out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
}

static bool encrypt_entire_file(FILE* src, uint64_t size, const char* destination, uint16_t content_id){
    bool r = false;
    uint8_t* enc = malloc(BLOCK_SIZE);
    uint8_t* dec = malloc(BLOCK_SIZE);
    assert(enc != NULL);
    assert(dec != NULL);
    uint64_t written = 0;
    uint64_t block_number = 0;

    FILE* dst = fopen_utf8(destination, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", destination);
        goto out;
    }
    
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_id;

    uint64_t initialSize = size;
    char progress[20] = "";
    uint16_t progress_length = 0;
    uint64_t percentage = 0;
    fseek64(src, 0, SEEK_SET);
    while (size > 0) {
        if(block_number == 0){
            progress_length = strlen(progress);
            for(uint8_t i = 0; i < progress_length; i++){
                printf("\b \b");
            }
            percentage = (100 * (initialSize - size)) / initialSize;
            sprintf(progress, "%" PRIu64 " %%", percentage);
            printf("%s", progress);
        }
        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes to '%s'\n", BLOCK_SIZE, destination);
            goto out;
        }

        aes_crypt_cbc(&ectx, AES_ENCRYPT, BLOCK_SIZE, iv, (const uint8_t*)(enc), (uint8_t*)dec);

        size -= fwrite(dec, sizeof(char), BLOCK_SIZE, dst);

        block_number++;
        if (block_number >= 16)
            block_number = 0;
    }
    progress_length = strlen(progress);
    for(uint8_t i = 0; i < progress_length; i++){
        printf("\b \b");
    }
    printf("100 %%\n");
    r = true;
out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
    return r;
}
static bool extract_file(FILE* src, uint64_t part_data_offset, uint64_t file_offset,
                         uint64_t size, const char* path, uint16_t content_id)
{
    bool r = false;
    uint8_t* enc = malloc(BLOCK_SIZE);
    uint8_t* dec = malloc(BLOCK_SIZE);
    assert(enc != NULL);
    assert(dec != NULL);
    uint64_t written = 0;

    // Calc real offset
    uint64_t roffset = file_offset / BLOCK_SIZE * BLOCK_SIZE;
    uint64_t soffset = file_offset - (file_offset / BLOCK_SIZE * BLOCK_SIZE);

    FILE* dst = fopen_utf8(path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", path);
        goto out;
    }
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_id;

    uint64_t write_size = BLOCK_SIZE;

    if (soffset + size > write_size)
        write_size = write_size - soffset;

    fseek64(src, part_data_offset + roffset, SEEK_SET);

    while (size > 0) {
        if (write_size > size)
            write_size = size;

        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes from '%s'\n", BLOCK_SIZE, path);
            goto out;
        }

        aes_crypt_cbc(&ctx, AES_DECRYPT, BLOCK_SIZE, iv, (const uint8_t*)(enc), (uint8_t*)dec);

        size -= fwrite(dec + soffset, sizeof(char), (size_t)write_size, dst);

        written += write_size;

        if (soffset) {
            write_size = BLOCK_SIZE;
            soffset = 0;
        }
    }

    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
}
#undef BLOCK_SIZE

bool copyFile(char * _src, char * _dest);

bool decrypt_blob(BaseBlob * baseBlob, char * fst_path){
    bool r = false;
    char path[PATH_MAX];
    char hpath[PATH_MAX];
    char h3[PATH_MAX];
    char h3_source[PATH_MAX];
    char h3_destination[PATH_MAX];
    FILE * src = NULL;
    // sprintf(fst_path, "game\\0000000a.app");
    if (strcmp(baseBlob->blobPath, fst_path) != 0) {//dont decrypt fst
        if(baseBlob->type == HASH){
            for (uint32_t k = 0; k < array_size(pattern_h3); k++) {//Give up if the blob don't exist
                sprintf(h3_source, pattern_h3[k], input_directory, PATH_SEP, baseBlob->content_id);
                sprintf(h3_destination, pattern_h3[k], destination_directory, PATH_SEP, baseBlob->content_id);
                if (is_file(h3_source))
                    break;
            }
            printf("Copying file '%s'\n", h3_source);
            if(is_file(h3_destination)){
                fprintf(stderr, "ERROR: '%s' were supposed to be copied only once\n", h3_destination);
                goto out;
            }
            if (!copyFile(h3_source, h3_destination)){
                fprintf(stderr, "ERROR: Could not write: '%s'\n", h3_destination);
                goto out;
            }

            printf("Decrypting file '%s' ", baseBlob->blobPath);
            src = fopen_utf8(baseBlob->blobPath, "rb");//Open the source blob
            sprintf(path, "%s.cfk", baseBlob->destination);
            sprintf(hpath, "%s.hfk", baseBlob->destination);
            r = decrypt_entire_file_hash(src, baseBlob->length, path, baseBlob->content_id, hpath);
        }else if(baseBlob->type == ENCRYPTED){
            printf("Decrypting file '%s' ", baseBlob->blobPath);
            src = fopen_utf8(baseBlob->blobPath, "rb");
            sprintf(path, "%s.cfk", baseBlob->destination);
            r = decrypt_entire_file(src, baseBlob->length, path, baseBlob->content_id);
        }else{
            fprintf(stderr, "ERROR: The file '%s' is of an unknown type\n", baseBlob->blobPath);
            goto out;
        }
    }else{
        r = true;
    }
out:
    if(src != NULL)
        fclose(src);
    return r;
}

bool encrypt_blob(BaseBlob * baseBlob, char * fst_path){
    bool r = false;
    char path[PATH_MAX];
    char hpath[PATH_MAX];
    char h3[PATH_MAX];
    char h3_source[PATH_MAX];
    char h3_destination[PATH_MAX];
    FILE * src = NULL;
    FILE * hsrc = NULL;
    // sprintf(fst_path, "game\\0000000a.app");
    if (strcmp(baseBlob->blobPath, fst_path) != 0) {
        if(baseBlob->type == HASH){
            for (uint32_t k = 0; k < array_size(pattern_h3); k++) {//Give up if the blob don't exist
                sprintf(h3_source, pattern_h3[k], input_directory, PATH_SEP, baseBlob->content_id);
                sprintf(h3_destination, pattern_h3[k], destination_directory, PATH_SEP, baseBlob->content_id);
                if (is_file(h3_source))
                    break;
            }
            printf("Copying file '%s'\n", h3_source);
            if(is_file(h3_destination)){
                fprintf(stderr, "ERROR: '%s' were supposed to be copied only once\n", h3_destination);
                goto out;
            }
            if (!copyFile(h3_source, h3_destination)){
                fprintf(stderr, "ERROR: Could not write: '%s'\n", h3_destination);
                goto out;
            }

            printf("Encrypting file '%s.cfk' ", baseBlob->blobPath);
            sprintf(path, "%s.cfk", baseBlob->blobPath);
            sprintf(hpath, "%s.hfk", baseBlob->blobPath);
            src = fopen_utf8(path, "rb");//Open the source blob
            hsrc = fopen_utf8(hpath, "rb");//Open the source hash blob
            r = encrypt_entire_file_hash(src, hsrc, baseBlob->length, baseBlob->destination, baseBlob->content_id);            
        }else if(baseBlob->type == ENCRYPTED){
            printf("Encrypting file '%s.cfk' ", baseBlob->blobPath);
            sprintf(path, "%s.cfk", baseBlob->blobPath);
            src = fopen_utf8(path, "rb");
            r = encrypt_entire_file(src, baseBlob->length, baseBlob->destination, baseBlob->content_id);
        }else{
            fprintf(stderr, "ERROR: The file '%s' is of an unknown type\n", baseBlob->blobPath);
            goto out;
        }
    }else{
        r = true;
    }
out:
    if(src != NULL)
        fclose(src);
    if(hsrc != NULL)
        fclose(hsrc);
    return r;
}

bool decrypt_all_blobs(BaseBlobSet * baseBlobSet, char * fst_path){
    BaseBlobSet * c = baseBlobSet;
    while(1){
        if(decrypt_blob(c->baseBlob, fst_path) == false){
            fprintf(stderr, "ERROR: The blob'%s' could not be decrypted\n", c->baseBlob->blobPath);
            return false;
        }
        if(c->nextSet == NULL){
            break;
        }
        c = c->nextSet;
    };
    return true;
}
bool encrypt_all_blobs(BaseBlobSet * baseBlobSet, char * fst_path){
    BaseBlobSet * c = baseBlobSet;
    while(1){
        if(encrypt_blob(c->baseBlob, fst_path) == false){
            fprintf(stderr, "ERROR: The blob '%s.cfk' could not be encrypted\n", c->baseBlob->blobPath);
            return false;
        }
        if(c->nextSet == NULL){
            break;
        }
        c = c->nextSet;
    };
    return true;
}
bool copyFile(char * _src, char * _dest){
    bool r = false;
    FILE * src = fopen_utf8(_src, "rb");
    if (src == NULL) {
        fprintf(stderr, "ERROR: Could not open '%s'\n", _src);
        goto out;
    }
    FILE * dest= fopen_utf8(_dest, "wb");
    if (dest == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", _dest);
        goto out;
    }
    uint8_t* enc = malloc(1);
    fseek64(src, 0, SEEK_END);
    uint64_t file_size = ftell(src);
    fseek64(src, 0, SEEK_SET);
    while(file_size > 0){
        if (fread(enc, sizeof(char), 1, src) != 1) {
            fprintf(stderr, "ERROR: Could not read '%s'\n", _src);
            goto out;
        }
        file_size -= fwrite(enc, sizeof(char), 1, dest);
    }
    r = true;
out:
    if (src != NULL)
        fclose(src);
    if(dest != NULL)
        fclose(dest);
    free(enc);
    return r;
}

bool copyFileStrict(char * _src, char * _dest){
    bool r = false;
    if(is_directory(_dest)){
        fprintf(stderr, "ERROR: '%s' is a directory\n", _src);
        goto out;
    }
    if(is_file(_dest)){
        fprintf(stderr, "ERROR: '%s' is a preexisting file\n", _src);
        goto out;
    }
    r = copyFile(_src, _dest);
out:
    return r;
}
int main(int argc, char** argv){
    int r = EXIT_FAILURE; //Temporary store for the exit code
    
    char temp_fst_path[PATH_MAX];
    char fst_path[PATH_MAX];
    char destination_fst_path[PATH_MAX];
    char decrypted_fst_path[PATH_MAX];

    char current_app[PATH_MAX];
    char destination_app[PATH_MAX];

    char current_app_cfk[PATH_MAX];
    char destination_app_cfk[PATH_MAX];

    char *tmd_path = NULL;
    char tmd_destination[PATH_MAX];
    char *tik_path = NULL;
    char tik_destination[PATH_MAX];
    char *cert_path = NULL;
    char cert_destination[PATH_MAX];
    
    FILE* src = NULL;//Pointer to the source blobs
    TitleMetaData* tmd = NULL;//Pointer for title metadata, a structure that will be automatically filled
    uint8_t *tik = NULL, *fst_content = NULL;
    //Pattern for the file names

    if (argc < 3) {
        printf("%s %s - Wii U NUS package decrypter and reencrypter\n"
            "Copyright (c) 2022-2023 leonardo the human, \n"
            "Copyright (c) 2020-2021 VitaSmith, Copyright (c) 2013-2015 crediar\n"
            "Visit https://github.com/leonardothehuman/cafeKit for official source and downloads.\n\n"
            "Usage: %s [-d|-e] <source directory> <destination directory (optional)>\n"
            "\t-d|--decrypt: Decrypt the source directory into the destination\n"
            "\t-e|--encrypt: Encrypt the source directory into the destination\n\n"
            "This program is free software; you can redistribute it and/or modify it under\n"
            "the terms of the GNU General Public License as published by the Free Software\n"
            "Foundation; either version 3 of the License or any later version.\n",
            _appname(argv[0]), VER_STRING, _appname(argv[0]));
        return EXIT_SUCCESS;
    }

    if(strcmp(argv[1], "-d") == 0 || strcmp(argv[1], "-D") == 0 || strcmp(argv[1], "--decrypt") == 0 || strcmp(argv[1], "--DECRYPT") == 0){
        application_mode = DECRYPT;
    }else if(strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-E") == 0 || strcmp(argv[1], "--encrypt") == 0 || strcmp(argv[1], "--ENCRYPT") == 0){
        application_mode = ENCRYPT;
    }else{
        printf("Incorrect operation mode");
        return EXIT_SUCCESS;
    }

    if (!is_directory(argv[2])) {
        printf("You must specify a directory as source");
        return EXIT_SUCCESS;
        uint8_t* buf = NULL;
        uint32_t size = read_file_max(argv[2], &buf, T_MAGIC_OFFSET + sizeof(uint64_t));
        if (size == 0)
            goto out;
        if (size >= T_MAGIC_OFFSET + sizeof(uint64_t)) {
            uint64_t magic = getbe64(&buf[T_MAGIC_OFFSET]);
            free(buf);
            if (magic == TMD_MAGIC) {
                tmd_path = strdup(argv[2]);
                if (argc < 4) {
                    tik_path = strdup(argv[2]);
                    tik_path[strlen(tik_path) - 2] = 'i';
                    tik_path[strlen(tik_path) - 1] = 'k';
                } else {
                    tik_path = strdup(argv[3]);
                }
            } else if (magic == TIK_MAGIC) {
                tik_path = strdup(argv[2]);
                if (argc < 4) {
                    tmd_path = strdup(argv[2]);
                    tmd_path[strlen(tik_path) - 2] = 'm';
                    tmd_path[strlen(tik_path) - 1] = 'd';
                } else {
                    tmd_path = strdup(argv[3]);
                }
            }
        }

        input_directory = strdup(argv[2]);
        // We'll need the current path for locating files, which we set in argv[1]
        argv[2][get_trailing_slash(argv[2])] = 0;
        if (argv[2][0] == 0) {
            argv[2][0] = '.';
            argv[2][1] = 0;
        }
        free(input_directory);
    }
    input_directory = strdup(argv[2]);

    // If the condition below is true, argv[1] is a directory
    if ((tmd_path == NULL) || (tik_path == NULL)) {
        size_t size = strlen(argv[2]);
        free(tmd_path);
        free(tik_path);
        tmd_path = calloc(size + 16, 1);
        tik_path = calloc(size + 16, 1);
        cert_path = calloc(size + 17, 1);
        sprintf(tmd_path, "%s%ctitle.tmd", argv[2], PATH_SEP);
        sprintf(tik_path, "%s%ctitle.tik", argv[2], PATH_SEP);
        sprintf(cert_path, "%s%ctitle.cert", argv[2], PATH_SEP);
    }

    uint32_t tmd_len = read_file(tmd_path, (uint8_t**)&tmd);
    if (tmd_len == 0)
        goto out;

    uint32_t tik_len = read_file(tik_path, &tik);
    if (tik_len == 0)
        goto out;

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    printf("Title version:%u\n", getbe16(&tmd->TitleVersion));
    printf("Content count:%u\n", getbe16(&tmd->ContentCount));

    //Verifies and sets the correct decryption keys to decrypt the title's encryptation key
    if (strcmp((char*)(&tmd->Issuer), "Root-CA00000003-CP0000000b") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonKey, sizeof(WiiUCommonKey) * 8);
        aes_setkey_enc(&ectx, WiiUCommonKey, sizeof(WiiUCommonKey) * 8);
    } else if (strcmp((char*)(&tmd->Issuer), "Root-CA00000004-CP00000010") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8);
        aes_setkey_enc(&ectx, WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8);
    } else {
        fprintf(stderr, "ERROR: Unknown Root type: '%s'\n", (char*)tmd + 0x140);
        goto out;
    }

    memset(title_id, 0, sizeof(title_id)); //Clean the garbage

    memcpy(title_id, &tmd->TitleID, 8); //Sets the title id
    memcpy(title_key, tik + 0x1BF, 16); //Gets the encrypted title key from the ticket

    aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(title_key), title_id, title_key, title_key); //Descriptografa a chave
    //The title_id is the initialization vector
    aes_setkey_dec(&ctx, title_key, sizeof(title_key) * 8);//Sets the title specific encription key
    aes_setkey_enc(&ectx, title_key, sizeof(title_key) * 8);//Sets the title specific encription key

    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));//Generates a clean inicialization vector

    //Tries to guess the name of the FST file from something that is on metadata
    //Guess only the ones that ends with .app and reads the file
    for (uint32_t k = 0; k < (array_size(pattern_path) / 2); k++) {
        sprintf(temp_fst_path, pattern_path[k], argv[2], PATH_SEP, getbe32(&tmd->Contents[0].ID));
        if (is_file(temp_fst_path))
            break;
    }
    sprintf(fst_path, "%s", temp_fst_path);

    uint32_t fst_cnt_len = read_file(fst_path, &fst_content);
    //If the file with app in name does not exists, try to guess again without .app
    //And reads the file
    if (fst_cnt_len == 0) {
        for (uint32_t k = (array_size(pattern_path) / 2); k < array_size(pattern_path); k++) {
            sprintf(temp_fst_path, pattern_path[k], argv[2], PATH_SEP, getbe32(&tmd->Contents[0].ID));
            if (is_file(temp_fst_path))
                break;
        }
        fst_cnt_len = read_file(temp_fst_path, &fst_content);
        if (fst_cnt_len == 0)
            goto out;

        sprintf(fst_path, "%s", temp_fst_path);
    }

    //Check if the file size matches with the size on metadata
    if (getbe64(&tmd->Contents[0].Size) != (uint64_t)fst_cnt_len) {
        fprintf(stderr, "ERROR: Size of content %u is wrong: %u:%" PRIu64 "\n",
            getbe32(&tmd->Contents[0].ID), fst_cnt_len, getbe64(&tmd->Contents[0].Size));
        goto out;
    }

    // fprintf(stderr, "ERROR: Size of content %08x is wrong: %u:%" PRIu64 "\n",
    //         getbe32(&tmd->Contents[0].ID), fst_cnt_len, getbe64(&tmd->Contents[0].Size));

    //Decripts the FST file
    aes_crypt_cbc(&ctx, AES_DECRYPT, fst_cnt_len, iv, fst_content, fst_content);

    //Checks if the FST_MAGIC matches what is on the decrypted first file
    //Saves an unencrypted copy if dont matches
    if (getbe32(fst_content) != FST_MAGIC) {
        sprintf(decrypted_fst_path, "%s%c%08X.dec", argv[2], PATH_SEP, getbe32(&tmd->Contents[0].ID));
        fprintf(stderr, "ERROR: Unexpected content magic. Dumping decrypted file as '%s'.\n", decrypted_fst_path);
        file_dump(decrypted_fst_path, fst_content, fst_cnt_len);
        goto out;
    }

    struct FST* fst = (struct FST*)fst_content;

    printf("FSTInfo Entries: %u\n", getbe32(&fst->EntryCount));
    //Checks if the fst have more info entries than what is allowed
    if (getbe32(&fst->EntryCount) > MAX_ENTRIES) {
        fprintf(stderr, "ERROR: Too many entries\n");
        goto out;
    }

    //Points to the file entry of the fst file
    struct FEntry* fe = (struct FEntry*)(fst_content + 0x20 + (uintptr_t)getbe32(&fst->EntryCount) * 0x20);

    //Gets the file entries count
    uint32_t entries = getbe32(fst_content + 0x20 + (uintptr_t)getbe32(&fst->EntryCount) * 0x20 + 8);
    //Offset of where the names are stored
    uint32_t name_offset = 0x20 + getbe32(&fst->EntryCount) * 0x20 + entries * 0x10;

    printf("FST entries: %u\n", entries);
    
    char* dst_dir = ((argc <= 3) || is_file(argv[3])) ? argv[2] : argv[3]; //Process the destination directory
    if(argc <= 3){
        sprintf(destination_directory, "%s%cout", argv[2], PATH_SEP);
    }else{
        sprintf(destination_directory, "%s%c", argv[3], PATH_SEP);
    }

    for (uint32_t k = 0; k < array_size(pattern_path); k++) {
        sprintf(temp_fst_path, pattern_path[k], argv[2], PATH_SEP, getbe32(&tmd->Contents[0].ID));
        sprintf(destination_fst_path, pattern_path[k], destination_directory, PATH_SEP, getbe32(&tmd->Contents[0].ID));
        if (is_file(temp_fst_path))
            break;
    }

    BaseBlobSet * mainBlobSet = NULL;

    create_path(destination_directory);//Create the destination directory if dont exists
    if(dir_empty(destination_directory) == 0){
        printf("ERROR: The destination directory '%s' is not empty", destination_directory);
        goto out;
    }
    if(dir_empty(destination_directory) < 0){
        printf("ERROR: Could not read '%s'", destination_directory);
        goto out;
    }

    if(application_mode == DECRYPT){
        printf("Decrypting to directory: '%s'\n", destination_directory);
    }else{
        printf("Encrypting to directory: '%s'\n", destination_directory);
    }

    printf("Copying file '%s'\n", temp_fst_path);
    if(copyFile(temp_fst_path, destination_fst_path) == false){
        fprintf(stderr, "ERROR: could not copy the file %s\n", temp_fst_path);
        goto out;
    }
    
    char path[PATH_MAX] = { 0 };//Temporary store of each destination file
    uint32_t entry[16];//Stores entries indexes when level changes
    uint32_t l_entry[16];//Stores the NextOffset of the current level when level changes
    //Sems like NextOffset is the index of the entry where we will go back a level

    uint32_t level = 0;//Marks the current directory level inside the package

    for (uint32_t i = 1; i < entries; i++) {
        if (level > 0) {//Go to the parend directory if needed
            while ((level >= 1) && (l_entry[level - 1] == i))
                level--;
        }

        if (fe[i].Type & 1) {//Increments the level and stores indexes if the entry is for the next level
            entry[level] = i;
            l_entry[level++] = getbe32(&fe[i].NextOffset);
            if (level >= MAX_LEVELS) {
                fprintf(stderr, "ERROR: Too many levels\n");
                break;
            }
        } else {
            uint32_t offset;//Offset for the address where the entry file name will go
            memset(path, 0, sizeof(path));//Fills the variable with string terminator just to be safe
            strcpy(path, dst_dir);//Puts the destination directory on the path

            size_t short_path = strlen(path) + 1;//Stores the separator betwen the base output path and the path inside the package
            for (uint32_t j = 0; j < level; j++) {//Navigates trough levels to make the complete path then creates the directory where the file will output
                path[strlen(path)] = PATH_SEP;
                offset = getbe32(&fe[entry[j]].TypeName) & 0x00FFFFFF;
                memcpy(path + strlen(path), fst_content + name_offset + offset, strlen((char*)fst_content + name_offset + offset));
            }
            //Finally adds the name of the file to the path
            path[strlen(path)] = PATH_SEP;
            offset = getbe32(&fe[i].TypeName) & 0x00FFFFFF;
            memcpy(path + strlen(path), fst_content + name_offset + offset, strlen((char*)fst_content + name_offset + offset));

            //Now we can get the offset of the file content !!!
            uint64_t cnt_offset = ((uint64_t)getbe32(&fe[i].FileOffset));
            if ((getbe16(&fe[i].Flags) & 4) == 0)//If this flag is set, the offset is multiplied by 32
                cnt_offset <<= 5;

            // printf("Size:%07X Offset:0x%010" PRIx64 " CID:%02X U:%02X %s\n", getbe32(&fe[i].FileLength),
            //     cnt_offset, getbe16(&fe[i].ContentID), getbe16(&fe[i].Flags), &path[short_path]);

            //Gets the file id for the current entry, to determine the source blob
            uint32_t cnt_file_id = getbe32(&tmd->Contents[getbe16(&fe[i].ContentID)].ID);

            if (!(fe[i].Type & 0x80)) {//Some type of entries can not be extracted
                // Handle upper/lowercase for target as well as files without extension
                for (uint32_t k = 0; k < array_size(pattern_path); k++) {//Give up if the blob don't exist
                    sprintf(current_app, pattern_path[k], argv[2], PATH_SEP, cnt_file_id);
                    sprintf(destination_app, pattern_path[k], destination_directory, PATH_SEP, cnt_file_id);
                    // printf("{{%s}}", name);
                    if(application_mode == DECRYPT){
                        if (is_file(current_app))
                            break;
                    }else{
                        sprintf(current_app_cfk, "%s%s", current_app, ".cfk");
                        if (is_file(current_app_cfk))
                            break;
                    }
                }
                if(application_mode == DECRYPT){
                    src = fopen_utf8(current_app, "rb");//Open the source blob
                    if (src == NULL) {
                        fprintf(stderr, "ERROR: Could not open: '%s'\n", current_app);
                        goto out;
                    }
                }else{
                    src = fopen_utf8(current_app_cfk, "rb");//Open the source blob
                    if (src == NULL) {
                        fprintf(stderr, "ERROR: Could not open: '%s'\n", current_app_cfk);
                        goto out;
                    }
                }
                fseek(src, 0, SEEK_END); // seek to end of file
                uint64_t current_app_size = ftell(src); // get current file pointer
                
                if ((getbe16(&fe[i].Flags) & 0x440)) {//Determines if the extraction will be normal or hash
                    // if (!extract_file_hash(src, 0, cnt_offset, getbe32(&fe[i].FileLength), path, getbe16(&fe[i].ContentID)))
                    //     goto out;
                    // printf("{{%s}}\n", current_app);
                    llnb_attach_region(
                        llnb_add_BaseBlob_to_set(
                            current_app,
                            destination_app,
                            current_app_size,
                            &mainBlobSet
                        ),
                        NULL,
                        cnt_offset,
                        getbe32(&fe[i].FileLength),
                        getbe16(&fe[i].ContentID),
                        HASH
                    );
                } else {
                    // if (!extract_file(src, 0, cnt_offset, getbe32(&fe[i].FileLength), path, getbe16(&fe[i].ContentID)))
                    //     goto out;
                    llnb_attach_region(
                        llnb_add_BaseBlob_to_set(
                            current_app,
                            destination_app,
                            current_app_size,
                            &mainBlobSet
                        ),
                        NULL,
                        cnt_offset,
                        getbe32(&fe[i].FileLength),
                        getbe16(&fe[i].ContentID),
                        ENCRYPTED
                    );
                }
                fclose(src);
                src = NULL;
            }else{
                // printf("not");
            }
        }
    }
    if(llnb_calculate_base_fields(mainBlobSet) == false){
        fprintf(stderr, "ERROR: An input file should not have multiple content_id's or content with different type \n");
        llnb_print_BaseBlobSet(mainBlobSet);
        goto out;
    }
    // llnb_print_BaseBlobSet(mainBlobSet);
    if(application_mode == DECRYPT){
        if(decrypt_all_blobs(mainBlobSet, fst_path) == false){
            fprintf(stderr, "ERROR: Could not decrypt all blobs \n");
            goto out;
        }
    }else{
        if(encrypt_all_blobs(mainBlobSet, fst_path) == false){
            fprintf(stderr, "ERROR: Could not encrypt all blobs \n");
            goto out;
        }
    }

    
    struct dirent *ent;
    char unk_dst[PATH_MAX]; //The destination file
    char unk_ndst[PATH_MAX]; //Destination file after adding the unknown file extension
    char unk_cfk[PATH_MAX]; //Destination file after adding cafe kit file extension
    char unk_src[PATH_MAX]; //The source file
    DIR *d = opendir(argv[2]);
    if (!d) {
        fprintf(stderr, "ERROR: Could not open %s\n", path);
        goto out;
    }

//sprintf(destination_directory, "%s%c", argv[3], PATH_SEP);
    while ((ent = readdir(d))) {
        if (!strcmp(ent->d_name, ".") || !(strcmp(ent->d_name, "..")))
            continue;
        if(is_directory(ent->d_name))
            continue;

        sprintf(unk_src, "%s%c%s", argv[2], PATH_SEP, ent->d_name);
        sprintf(unk_dst, "%s%c%s", destination_directory, PATH_SEP, ent->d_name);
        if(application_mode == DECRYPT){
            sprintf(unk_ndst, "%s%c%s.cuk", destination_directory, PATH_SEP, ent->d_name);
            sprintf(unk_cfk, "%s%c%s.cfk", destination_directory, PATH_SEP, ent->d_name);
            
            if(
                (endsWith(ent->d_name, ".app") || endsWith(ent->d_name, ".APP")) &&
                (!is_file(unk_cfk) && !is_file(unk_dst))
            ){
                if(copyFileStrict(unk_src, unk_ndst) == false){
                    fprintf(stderr, "ERROR: could not copy the file %s\n", unk_src);
                    goto out;
                }
                printf("Unknown file copy: %s\n", ent->d_name);
            }

            if(
                (endsWith(ent->d_name, ".h3") || endsWith(ent->d_name, ".H3")) &&
                !is_file(unk_dst)
            ){
                if(copyFileStrict(unk_src, unk_ndst) == false){
                    fprintf(stderr, "ERROR: could not copy the file %s\n", unk_src);
                    goto out;
                }
                printf("Unknown file copy: %s\n", ent->d_name);
            }
        }else{
            if(endsWith(ent->d_name, ".cuk") || endsWith(ent->d_name, ".CUK")){
                int len = strlen(unk_dst);
                unk_dst[len - 4] = '\0';
                if(copyFileStrict(unk_src, unk_dst) == false){
                    fprintf(stderr, "ERROR: could not copy the file %s\n", unk_src);
                    goto out;
                }
                printf("Unknown file copy: %s\n", ent->d_name);
            }
        }
    }
    closedir(d);
    
    printf("Copying file '%s'\n", tik_path);
    sprintf(tik_destination, "%s%ctitle.tik", destination_directory, PATH_SEP);
    if(copyFile(tik_path, tik_destination) == false){
        fprintf(stderr, "ERROR: Could not copy the ticket file \n");
        goto out;
    }

    printf("Copying file '%s'\n", tmd_path);
    sprintf(tmd_destination, "%s%ctitle.tmd", destination_directory, PATH_SEP);
    if(copyFile(tmd_path, tmd_destination) == false){
        fprintf(stderr, "ERROR: Could not copy the metadata file \n");
        goto out;
    }

    printf("Copying file '%s'\n", cert_path);
    sprintf(cert_destination, "%s%ctitle.cert", destination_directory, PATH_SEP);
    if(copyFile(cert_path, cert_destination) == false){
        fprintf(stderr, "ERROR: could not copy the certificate file \n");
        goto out;
    }

    r = EXIT_SUCCESS;

out:
 //   llnb_print_BaseBlobSet(mainBlobSet);
    if(mainBlobSet != NULL)
        llnb_free_BaseBlobSet(&mainBlobSet);
    if(tmd != NULL)
        free(tmd);
    if(tik != NULL)
        free(tik);
    if(fst_content != NULL)
        free(fst_content);
    if(tmd_path != NULL)
        free(tmd_path);
    if(tik_path != NULL)
        free(tik_path);
    if (src != NULL)
        fclose(src);

    if(r == EXIT_SUCCESS){
        if(application_mode == DECRYPT){
            printf("\nWup package has been succefuly decrypted.\n");
            printf("\nPlease, don't blindly trust 100%% in this tool yet, you should reencrypt\n");
            printf("the package and use a tool like HashCheck Shell Extension and a diff\n");
            printf("checker to verify if the output matches the input before deleting\n");
            printf("the original package\n");
        }else{
            printf("\nWup package has been succefuly encrypted.\n");
        }
    }else{
        if(application_mode == DECRYPT){
            fprintf(stderr, "\nERROR: IT WAS NOT POSSIBLE TO COMPLETE THE DECRYPTION\n");
            fprintf(stderr, "OPERATION, DELETE THE OUTPUT DIRECTORY AND TRY AGAIN ...\n");
        }else{
            fprintf(stderr, "\nERROR: IT WAS NOT POSSIBLE TO COMPLETE THE ENCRYPTION\n");
            fprintf(stderr, "OPERATION, DELETE THE OUTPUT DIRECTORY AND TRY AGAIN ...\n");
        }
    }
    return r;
}

//CALL_MAIN
