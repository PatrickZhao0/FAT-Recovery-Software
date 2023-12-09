#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>


#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)


void print_usage(int exit_status);
void print_fsinfo(BootEntry* boot_entry);
int cluster_addr(BootEntry* boot_entry, int cluster_num);
void list_root_dir(char* disk_start, BootEntry* boot_entry, int* FAT);
void con_recover(char* disk_start, BootEntry* boot_entry, int* FAT, char* filename);

int main(int argc, char** argv){
    char* filename = NULL;
    char* hash_str;
    char* disk_image = argv[1];
    if (argc < 2 || argv[1][0] == '-') {
        print_usage(EXIT_SUCCESS);
    }
    int fd;
    if ((fd = open(argv[1], O_RDWR)) == -1)
        print_usage(EXIT_FAILURE);
    struct stat sb;
    if (fstat(fd, &sb) == -1)
        print_usage(EXIT_FAILURE);
    char* disk_start = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (disk_start == MAP_FAILED)
        print_usage(EXIT_FAILURE);

    BootEntry* boot_entry = (BootEntry*) disk_start;
    int FAT_size_in_byte = (int)(boot_entry->BPB_FATSz32 * boot_entry ->BPB_BytsPerSec);
    int cluster_size_in_byte = (int)(boot_entry->BPB_BytsPerSec * boot_entry->BPB_SecPerClus);
    char* data_start = disk_start + boot_entry-> BPB_RsvdSecCnt * boot_entry->BPB_BytsPerSec + boot_entry->BPB_NumFATs * FAT_size_in_byte;
    char* root_dir_start = data_start + (boot_entry->BPB_RootClus - 2)*cluster_size_in_byte;
    int* FAT = (int*)(disk_start + boot_entry->BPB_RsvdSecCnt * boot_entry->BPB_BytsPerSec);
    
    optind = 2;
    int option;
    int iflag = 0;
    int lflag = 0;
    int rflag = 0;
    int Rflag = 0;
    int sflag = 0;
    while ((option = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (option) {
            case 'i':
                if(optind < argc) print_usage(EXIT_FAILURE);
                iflag = 1;
                print_fsinfo(boot_entry);
                exit(EXIT_SUCCESS);
                break;
            case 'l':
                if(optind < argc) print_usage(EXIT_FAILURE);
                list_root_dir(disk_start, boot_entry, FAT);
                lflag = 1;
                exit(EXIT_SUCCESS);
                break;
            case 'r':
                rflag = 1;
                filename = optarg;
                break;
            case 'R':
                Rflag = 1;
                filename = optarg;
                break;
            case 's':
                sflag = 1;
                if(!Rflag && !rflag) print_usage(EXIT_FAILURE);
                hash_str = optarg;
                break;
            case '?':
                print_usage(EXIT_FAILURE);
                break;
            default:
                break;
        }
    }

    if ( (Rflag && !sflag) || (iflag + lflag + Rflag + rflag != 1)) {
        print_usage(EXIT_FAILURE);
    }
    if (Rflag)
        printf("R");
    if (rflag)
        con_recover(disk_start, boot_entry, FAT, filename);
    return 0;
}

void print_usage(int exit_status){
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(exit_status);
}

void print_fsinfo(BootEntry* boot_entry){
    printf("Number of FATs = %d\n", (int) boot_entry->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", (int) boot_entry->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", (int) boot_entry->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", (int) boot_entry->BPB_RsvdSecCnt);
}

void list_root_dir(char* disk_start, BootEntry* boot_entry, int* FAT){
    int curr_clus = (int) boot_entry->BPB_RootClus;
    char* start_addr;
    int total_entries = 0;
    do{
        int entries_remaining_in_cluster = (int)((boot_entry->BPB_BytsPerSec * boot_entry->BPB_SecPerClus) / sizeof(DirEntry));
        start_addr = disk_start + cluster_addr(boot_entry, curr_clus);
        int offset = 0;

        while(entries_remaining_in_cluster > 0){
            DirEntry* dir_entry = (DirEntry*)(start_addr + offset);

            offset += sizeof(DirEntry);
            entries_remaining_in_cluster -= 1;

            if(dir_entry->DIR_Name[0] == 0) break;
            if (dir_entry->DIR_Name[0] == 0xe5)continue;

            int is_directory = (dir_entry -> DIR_Attr & 0x10);
            for(int i = 0; i < 11; i++){
                
                if (i == 8 && !is_directory && dir_entry->DIR_Name[8] != ' ') 
                    printf(".");
                if (dir_entry->DIR_Name[i] != ' ') 
                    printf("%c", dir_entry->DIR_Name[i]);
                
            }

            int high = (int)dir_entry->DIR_FstClusHI;
            int low = (int)dir_entry->DIR_FstClusLO;
            int combined = (high << 16) | (low & 0xFFFF);
            if(is_directory){
                printf("/ (starting cluster = %d)\n", combined);
            }else if(dir_entry->DIR_FileSize == 0){
                printf(" (size = 0)\n");
            }else{
                printf(" (size = %d, starting cluster = %d)\n", (int)dir_entry->DIR_FileSize, combined);
            }

            total_entries ++;
        }

    }while((curr_clus = FAT[curr_clus]) < 0x0ffffff8);
    printf("Total number of entries = %d\n", total_entries);
}   

int cluster_addr(BootEntry* boot_entry, int cluster_num){
    int reserved_size = (int)(boot_entry->BPB_RsvdSecCnt * boot_entry->BPB_BytsPerSec);
    int FATs_size = (int)(boot_entry->BPB_NumFATs * (boot_entry->BPB_FATSz32 * boot_entry ->BPB_BytsPerSec));
    int cluster_size = (int)(boot_entry->BPB_BytsPerSec * boot_entry->BPB_SecPerClus);
    int cluster_offset = (cluster_num - 2) * cluster_size;
    return reserved_size + FATs_size + cluster_offset;
}

void con_recover(char* disk_start, BootEntry* boot_entry, int* FAT, char* filename){
    int curr_clus = (int) boot_entry->BPB_RootClus;
    char* start_addr;
    DirEntry* select_file = NULL;
    do{
        int entries_remaining_in_cluster = (int)((boot_entry->BPB_BytsPerSec * boot_entry->BPB_SecPerClus) / sizeof(DirEntry));
        start_addr = disk_start + cluster_addr(boot_entry, curr_clus);
        int offset = 0;

        while(entries_remaining_in_cluster > 0){
            DirEntry* dir_entry = (DirEntry*)(start_addr + offset);
            offset += sizeof(DirEntry);
            entries_remaining_in_cluster -= 1;
            if ( (dir_entry->DIR_Name[0] != 0xe5) || (dir_entry -> DIR_Attr & 0x10) )
                continue;
            char deleted_filename[15];
            int deleted_filename_index = 0;
            for(int i = 0; i < 11; i++){
                if (i == 8 && dir_entry->DIR_Name[8] != ' '){
                    deleted_filename[deleted_filename_index] = '.';
                    deleted_filename_index ++;
                }
                if (dir_entry->DIR_Name[i] != ' '){
                    deleted_filename[deleted_filename_index] = dir_entry->DIR_Name[i];
                    deleted_filename_index ++;
                }
            }
            deleted_filename[deleted_filename_index] = '\0';
            if(strcmp(deleted_filename+1, filename+1) == 0){
                if (select_file == NULL){
                    select_file = dir_entry;
                    continue;
                }else{
                    printf("%s: multiple candidates found\n", filename);
                    return;
                }
            }else{
                continue;       
            }
        }
    }while((curr_clus = FAT[curr_clus]) < 0x0ffffff8);
    
    if(select_file != NULL){
        select_file->DIR_Name[0] = filename[0];
        int high = (int)select_file->DIR_FstClusHI;
        int low = (int)select_file->DIR_FstClusLO;
        int combined = (high << 16) | (low & 0xFFFF);
        int cluster_size_in_byte = (int)(boot_entry->BPB_BytsPerSec * boot_entry->BPB_SecPerClus); 
        int clusters_span = (int) (select_file->DIR_FileSize / cluster_size_in_byte);
        if(select_file->DIR_FileSize % cluster_size_in_byte != 0) 
            clusters_span ++;
        for(int i = 1; i < clusters_span; i++){
            FAT[combined] = combined + 1;
            combined ++;
        }
        FAT[combined] = 0x0ffffff8;
        printf("%s: successfully recovered\n", filename);
    }else{
        printf("%s: file not found\n", filename);
    }
} 