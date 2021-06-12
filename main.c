#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "sys/stat.h"
#include <fcntl.h>
#include <unistd.h>


typedef struct {
    unsigned char   e_ident[EI_NIDENT];
    Elf32_Half      e_type;
    Elf32_Half      e_machine;
    Elf32_Word      e_version;
    Elf32_Addr      e_entry;
    Elf32_Off       e_phoff;
    Elf32_Off       e_shoff;
    Elf32_Word      e_flags;
    Elf32_Half      e_ehsize;
    Elf32_Half      e_phentsize;
    Elf32_Half      e_phnum;
    Elf32_Half      e_shentsize;
    Elf32_Half      e_shnum;
    Elf32_Half      e_shstrndx;
} Elf32_header;
typedef struct
{
  Elf32_Word	sh_name;		/* Section name (string tbl index) */
  Elf32_Word	sh_type;		/* Section type */
  Elf32_Word	sh_flags;		/* Section flags */
  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
  Elf32_Off	    sh_offset;		/* Section file offset */
  Elf32_Word	sh_size;		/* Section size in bytes */
  Elf32_Word	sh_link;		/* Link to another section */
  Elf32_Word	sh_info;		/* Additional section information */
  Elf32_Word	sh_addralign;		/* Section alignment */
  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
} Elf32_section;

typedef struct {
	Elf32_Word	st_name;
	Elf32_Addr	st_value;
	Elf32_Word	st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half	st_shndx;
} Elf32_Symtable;

int getFileSize(int fd){

    struct stat fileInfo;
    fstat(fd, &fileInfo);

    return fileInfo.st_size;
}

void printHeader(int fd){
    int fileSize = getFileSize(fd);
    void* mmapVar;

    mmapVar = mmap(NULL, fileSize,PROT_READ,MAP_PRIVATE,fd,0);
    Elf32_header* elfHeader = (Elf32_header *) mmapVar;

    printf("ELF Magic:\n");
    printf("Magic:\t\t\t\t");
    printf("\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x \n",elfHeader->e_ident[0], elfHeader->e_ident[1], elfHeader->e_ident[2], elfHeader->e_ident[2], elfHeader->e_ident[3], elfHeader->e_ident[4], elfHeader->e_ident[5], elfHeader->e_ident[6], elfHeader->e_ident[7], elfHeader->e_ident[8], elfHeader->e_ident[9], elfHeader->e_ident[10], elfHeader->e_ident[11], elfHeader->e_ident[12], elfHeader->e_ident[13], elfHeader->e_ident[14]);
    printf("Class: \t\t\t\t\tELF32\n");
    printf("Data\t\t\t\t\t%s\n",                                      (elfHeader->e_ident[5]==1 ? "2's complement, little endian" : "Big Endian"));
    printf("Version: \t\t\t\t%s\n",                                  (elfHeader->e_version == 1 ? "1 (current)" : "0 (none)"));
    printf("OS/ABI \t\t\t\t\t");
    switch(elfHeader->e_ident[EI_OSABI]){
        case 0:
        printf("UNIX - System V\n");
        break;
        case 1:
        printf("HP/UX\n");
        break;
        case 2:
        printf("NetBSD\n");
        break;
        case 3:
        printf("Object uses GNU ELF extensions\n");
        break;
        case 6:
        printf("Sun Solaris\n");
        break;
        case 7:
        printf("IBM AIX\n");
        break;
        case 8:
        printf("SGI IRIX\n");
        break;
        case 9:
        printf("FreeBSD\n");
        break;
        case 10:
        printf("Compaq TRU64 UNIX\n");
        break;
        case 11:
        printf("Novell Modesto\n");
        break;
        case 12:
        printf("OpenBSD\n");
        break;
        case 64:
        printf("ARM EABI\n");
        break;
        case 97:
        printf("ARM\n");
        break;
        case 255:
        printf("Standalone (embedded) application\n");
        break;
      


    }
    printf("ABI Version:\t\t\t\t%d\n\n",                             elfHeader->e_ident[EI_ABIVERSION]);
   
    printf("ELF Header:\n");
    printf("Type:\t\t\t\t\t");
     switch(elfHeader->e_type){
        case 0:
        printf("0x0000 (No file type)\n");
        break;
        case 1:
        printf("0x0001 (Relocatable file)\n");
        break;
        case 2:
        printf("0x0002 (Executable file)\n");
        break;
        case 3:
        printf("0x0003 (Shared object file)\n");
        break;
        case 4:
        printf("0x0004 (Core file)\n");
    }
    printf("Machine:\t\t\t\t%s\n", (elfHeader ->e_machine == 3 ? "0x0003 (Intel 80386)" : "0x0007 (Intel 80860)")); // Obstaja okoli 200 različnih kod za naprave. Uporabil sem dve kjer je velika verjetnost da bosta ti dve. V primeru da bi bilo vse potrebno bi samo dodal switch stavek
    printf("Version: \t\t\t\t%s\n",                                  (elfHeader->e_version == 1 ? "0x0001 (Current version)" : "0x0000 (None)"));

    printf("Entry point address:\t\t\t%#06x\n",                      elfHeader->e_entry);
    printf("Start of program headers\t\t%#06x\n",                    elfHeader->e_phoff);                         
    printf("Start of section headers:\t\t%#06x\n",                   elfHeader->e_shoff);
    printf("Flags:\t\t\t\t\t0x%04x\n",                              elfHeader->e_flags);
    printf("Size of this header:\t\t\t%#06x\n",                      elfHeader->e_ehsize);
    printf("Size of program headers:\t\t%#06x\n",                    elfHeader->e_phentsize);
    printf("Number of program headers:\t\t%#06x\n",                  elfHeader->e_phnum);
    printf("Size of section headers:\t\t%#06x\n",                    elfHeader->e_shentsize);
    printf("Number of section headers:\t\t%#06x\n",                  elfHeader->e_shnum);
    printf("Section header string table index:\t%#06x\n",             elfHeader->e_shstrndx);

}

void evenSpace(char* str){
     if(strlen(str) < 25){
            for(int j = 0; j < 25-strlen(str); j++){
                printf(" ");
            }
        }
}
void printTables(int fd){
    int fileSize = getFileSize(fd);
    int sectionNum;
    void* mmapVar;

    mmapVar = mmap(NULL, fileSize,PROT_READ,MAP_PRIVATE,fd,0);
    Elf32_header* elfHeader = (Elf32_header *) mmapVar;
    sectionNum = elfHeader->e_shnum;
    Elf32_section* elfSection = (Elf32_section *) (elfHeader->e_shoff + mmapVar + elfHeader->e_shstrndx*sizeof(Elf32_section));

    printf("Sekcije:\n          Ime                     Tip                                    Naslov                Odmik    Velikost\n");
    for(int i = 0; i < sectionNum; i++){
        Elf32_section* sectionHeader = (Elf32_section *) (elfHeader->e_shoff + mmapVar + i*sizeof(Elf32_section));

        char* name = elfSection->sh_offset + mmapVar + sectionHeader->sh_name;
        int address = sectionHeader->sh_addr;
        int type = sectionHeader->sh_type;
        int offset = sectionHeader->sh_offset;
        int size = sectionHeader->sh_size;


        printf("%03d    %s", i , name);
        if(strlen(name) < 25){
            for(int j = 0; j < 25-strlen(name); j++){
                printf(" ");
            }
        }
        switch(type){
            case 0:
            printf("NULL");
            evenSpace("NULL");
            break;
            case 1:
            printf("PROGBITS");
            evenSpace("PROGBITS");
            break;
            case 2:
            printf("SYMTAB");
            evenSpace("SYMTAB");
            break;
            case 3:
            printf("STRTAB");
            evenSpace("STRTAB");
            break;
            case 4:
            printf("RELA");
            evenSpace("RELA");
            break;
            case 5:
            printf("HASH");
            evenSpace("HASH");
            break;
            case 6:
            printf("DYNAMIC");
            evenSpace("DYNAMIC");
            break;
            case 7:
            printf("NOTE");
            evenSpace("NOTE");
            break;
            case 8:
            printf("NOBITS");
            evenSpace("NOBITS");
            break;
            case 9:
            printf("REL");
            evenSpace("REL");
            break;
            case 10:
            printf("SHLIB");
            evenSpace("SHLIB");
            break;
            case 11:
            printf("DYNSYM");
            evenSpace("DYNSYM");
            break;
            case 14:
            printf("INIT_ARRAY");
            evenSpace("INIT_ARRAY");
            break;
            case 15:
            printf("FINI_ARRAY");
            evenSpace("FINI_ARRAY");
            break;
            case 16:
            printf("PREINIT_ARRAY");
            evenSpace("PREINIT_ARRAY");
            break;
            case 17:
            printf("GROUP");
            evenSpace("GROUP");
            break;
            case 18:
            printf("SYMTABSHNDX");
            evenSpace("SYMTABSHNDX");
            break;
            case 19:
            printf("NUM");
            evenSpace("NUM");
            break;
            default:
            printf("UNDEFINED");
            evenSpace("UNDEFINED");
        }
        printf("               ");
        printf("%08x", address);
        printf("               ");
        printf("%06x", offset);
        printf("\t");
        printf("%06x \n", size);
    }
}
Elf32_Shdr* SYMTAB(void* mmapVar, int shoff, int headerEntries){
        Elf32_Shdr* symSection;

    for(int i = 0; i < headerEntries; i++) {
        Elf32_Shdr* section = (Elf32_Shdr*) (mmapVar + shoff + i*sizeof(Elf32_Shdr));
        if(section->sh_type == SHT_SYMTAB) {
            symSection = section;
            //printf("found");
            break;
        }
    }
    return symSection;
    
}
Elf32_Shdr* tableFinder(void* mmapVar, int shoff, int offset, int entries, char* comparer){
    Elf32_Shdr* strtabTable;
    
    for(int i = 0; i < entries; i++) {
       Elf32_Shdr* section = (Elf32_Shdr*) (mmapVar + shoff + i*sizeof(Elf32_Shdr));
        char* iterateSections = mmapVar + offset + section->sh_name;
        if(strcmp(iterateSections, comparer) == 0) {
            strtabTable = section;
            break;
        }
    }
    return  strtabTable;
}

void printObjdump(int fd, char* comparer){
    Elf32_Shdr* textSection;
    int fileSize = getFileSize(fd);
    int position;
    int address;
    char* printascii;
    unsigned char values;
    void* mmapVar = mmap(NULL, fileSize,PROT_READ,MAP_PRIVATE,fd,0);
    Elf32_Ehdr* elfHeader = (Elf32_Ehdr *) mmapVar;
    Elf32_Shdr* sectionTable = (Elf32_Shdr*) (elfHeader->e_shoff + elfHeader->e_shstrndx*sizeof(Elf32_Shdr) + mmapVar );
    textSection = tableFinder(mmapVar,elfHeader->e_shoff, sectionTable->sh_offset, elfHeader->e_shnum, comparer);
    address = textSection->sh_addr;
    int size = textSection->sh_size;
    char* offset = textSection->sh_offset + mmapVar;
    position = 0;
    int counter = 0;
    char ascii;
    while(position < textSection->sh_size){
        ascii = *(char *)(mmapVar + textSection->sh_offset + position);
        if(position % 16 == 0){
            printf("%02x ",address);
            address = address + 16;
            int hexCounter = 0;

    while (hexCounter < 16)
    {
        values = *(unsigned char *)(offset + position + hexCounter);
        if (position + hexCounter < size)
        {
            printf("%02x", values);
        }
        else
        {
            printf("  ");
        }
        hexCounter++;
        if (hexCounter % 4 == 0)
        {
            printf(" ");
        }
    }
  
  printf(" ");
            
    }
    if (ascii >= 32 && ascii < 127)
    {
        printf("%c", ascii);
    }
    else
    {
        printf(".");

    }
    position++;
    if (position % 16 == 0)
    {
	    printf("\n");

    }
    counter++;
    }
    	    printf("\n");

}
void printSymtable(int fd){
    int fileSize = getFileSize(fd);

    void* mmapVar = mmap(NULL, fileSize,PROT_READ,MAP_PRIVATE,fd,0);
    Elf32_Ehdr* elfHeader = (Elf32_Ehdr *) mmapVar;
    Elf32_Shdr* sectionTable = (Elf32_Shdr*) (elfHeader->e_shoff + elfHeader->e_shstrndx*sizeof(Elf32_Shdr) + mmapVar );
    int headerEntries = elfHeader->e_shnum;
    Elf32_Shdr* section;
    Elf32_Shdr* symSection;
    Elf32_Shdr* strtabTable;
    strtabTable = tableFinder(mmapVar, elfHeader->e_shoff, sectionTable->sh_offset, headerEntries, ".strtab");
    symSection = SYMTAB(mmapVar, elfHeader->e_shoff, headerEntries);
    //printf("Simboli:\n        Vrednost    Velikost      Ime\n");
    //printf("sh_size: %d         sizeof(Elf32Symtable): %d  \n", symSection->sh_size, sizeof(Elf32_Symtable));
    int i = 0;
    while(1) {
        Elf32_Sym* symbolTable = (Elf32_Sym*) (mmapVar + symSection->sh_offset + i*sizeof(Elf32_Sym));

        int value  = symbolTable->st_value;
        int size  = symbolTable->st_size;
        char* symbol_name  = mmapVar + strtabTable->sh_offset + symbolTable->st_name;

        if(strcmp(symbol_name, "SYMTAB") == 0){ //Symtab oznacuje konec
            break;
        }
        printf("  %03d %08x  ", i, value);
        printf("  %04x  ", size);
        printf("%s\n", symbol_name);
        i++;
    }
    //printf("Symtable: %d", symSection->sh_size / 115);

}

int main(int argc, char** argv) {
    int filefd;
    int fileSize;
    char cmd[8];
    char filePath[64];

    if(argc <  3){
        perror("Program za delovanje potrebuje zastavico [-h|-S|-s|-d ...] in pot do zbirke.");
        exit(-1);
    }
    else if(strcmp(argv[1], "-S") == 0 || strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "-h") == 0)
    {
        strcpy(filePath, argv[2]);
        filefd = open(filePath, O_RDONLY);
        if(filefd == -1){
            perror("Error occurred while opening file. The file may not exist!");
            exit(-1);
        }
    }
    else if(strcmp(argv[1], "-d") == 0){
        if(argc < 4){
            perror("Program za delovanje potrebuje zastavico [-h|-S|-s|-d ...] in pot do zbirke.");
             exit(-1);
        }
        strcpy(filePath, argv[3]);
        filefd = open(filePath, O_RDONLY);
         if(filefd == -1){
            perror("Error occurred while opening file. The file may not exist!");
            exit(-1);
        }
                char* comparer = argv[2];

        printObjdump(filefd, comparer);
    }


    if(strcmp(argv[1], "-h") == 0){
        printHeader(filefd);
    }
    else if(strcmp(argv[1], "-S") == 0){
        printTables(filefd);
    }
    else if(strcmp(argv[1], "-s") == 0 ){
        printSymtable(filefd);
    }
    



    return 0;
}