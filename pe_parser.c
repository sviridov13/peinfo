/*

Модуль обработки PE-файлов.

Маткин Илья Александрович   15.11.2012

*/


#include <windows.h>
#include <stdio.h>
#include <malloc.h>

#include "pe_parser.h"
#include "system.h"


//----------------------------------------


void PrintSectionInFileDump (PeHeaders *pe, unsigned int sectionNumber, unsigned int bytesPerLine);
void PrintSectionInMemoryDump (PeHeaders *pe, unsigned int sectionNumber, unsigned int bytesPerLine);

void PrintSectionsInFileDump (PeHeaders *pe, unsigned int bytesPerLine);
void PrintSectionsInMemoryDump (PeHeaders *pe, unsigned int bytesPerLine);

//----------------------------------------


//
// Загружает файл в память и заполняет структуру PeHeaders.
// В качестве аргумента принимает размер проецируемой части файла.
// Если передаётся ноль, то загружается весь файл.
//
BOOL LoadPeFile (char *filename, PeHeaders *pe, DWORD filesize) {


    pe->filename = filename;

    // открываем файл (получаем файловый дескриптор)
    pe->fd = CreateFile(filename ,      // имя файла
                        GENERIC_READ,   // права доступа
                        0,
                        NULL,
                        OPEN_EXISTING,          // открываемый файл должен существовать
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (pe->fd == INVALID_HANDLE_VALUE) {
        PrintLastErrorMessage();
        return FALSE;
        }

    if (filesize)
        pe->filesize = filesize;
    else
        pe->filesize = GetFileSize (pe->fd, NULL);

    // создаем проекцию файла в память
    pe->mapd = CreateFileMapping (pe->fd, NULL, PAGE_READONLY, 0, pe->filesize, NULL);
    if (pe->mapd == NULL) {
        CloseHandle(pe->fd);
        printf ("Error create file map\n");
        PrintLastErrorMessage();
        return FALSE;
        }

    // отображаем проекцию в память
    pe->mem = (PBYTE) MapViewOfFile (pe->mapd, FILE_MAP_READ, 0, 0, 0);
    if (pe->mem == NULL) {
        CloseHandle (pe->fd);
        CloseHandle (pe->mapd);
        printf ("Error mapping file\n");
        PrintLastErrorMessage();
        return FALSE;
        }

    // указатель на заголовок PE
    pe->doshead = (IMAGE_DOS_HEADER*) pe->mem;

    if (pe->doshead->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile (pe->mem);
        CloseHandle (pe->fd);
        CloseHandle (pe->mapd);
        printf ("Error DOS signature\n");
        return FALSE;
        }

    // указатель на NT заголовок
    pe->nthead = (IMAGE_NT_HEADERS*) ((unsigned int)pe->mem + pe->doshead->e_lfanew);

    if(pe->nthead->Signature != IMAGE_NT_SIGNATURE){
        UnmapViewOfFile (pe->mem);
        CloseHandle (pe->fd);
        CloseHandle (pe->mapd);
        printf("Error NT signature\n");
        return FALSE;
        }

    // получаем информацию о секциях
    pe->sections = (IMAGE_SECTION_HEADER*)((unsigned int) &(pe->nthead->OptionalHeader) + pe->nthead->FileHeader.SizeOfOptionalHeader);
    pe->countSec = pe->nthead->FileHeader.NumberOfSections;

    // получаем инфомацию об экспорте
    if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        pe->expdir = (IMAGE_EXPORT_DIRECTORY*)
            (pe->mem + RvaToOffset (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pe));
        pe->sizeExpdir = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }
    else {
        pe->expdir = 0;
        pe->sizeExpdir = 0;
        }

    // получаем информацию об импорте
    if (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        pe->impdir = (IMAGE_IMPORT_DESCRIPTOR*)
            (pe->mem + RvaToOffset (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pe));
        pe->sizeImpdir = pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
    else {
        pe->impdir = 0;
        pe->sizeImpdir = 0;
        }

    return TRUE;
}


//
// Выгружает PE файл (освобождает ресурсы).
//
void UnloadPeFile (PeHeaders *pe) {


    UnmapViewOfFile (pe->mem);
    CloseHandle (pe->fd);
    CloseHandle (pe->mapd);

    return;
}


//
// Возвращает файловое смещение по RVA.
//
DWORD RvaToOffset (DWORD rva, PeHeaders *pe) {

    unsigned int i;
    IMAGE_SECTION_HEADER *sections = pe->sections;
    unsigned int NumberSection = pe->countSec;


    if (rva > pe->nthead->OptionalHeader.SizeOfImage) {
        return 0;
        }

    //проходим по всем секциям и ищем
    //в какую попадает RVA
    for (i = 0; i < NumberSection; ++i) {
        if( (rva >= sections[i].VirtualAddress) && 
            (rva <= sections[i].VirtualAddress + sections[i].Misc.VirtualSize))
            return rva - sections[i].VirtualAddress + sections[i].PointerToRawData;
        }

    return 0;
}


//
// Выравнивает значение с кратностью align к верхней границе.
//
DWORD AlignToTop (DWORD value, DWORD align) {


    DWORD mask = ~ (align - 1);

    return (value + align - 1) & mask;
}


//
// Выравнивает значение с кратностью align к нижней границе.
//
DWORD AlignToBottom (DWORD value, DWORD align) {


    DWORD mask = ~ (align - 1);

    return value & mask;
}


//
// Возвращает индекс секции по имени
//
unsigned int GetSectionIndexByName (PeHeaders *pe, char *secname) {


    unsigned int indexSec;

    for (indexSec = 0; indexSec < pe->countSec; ++indexSec) {
        
        if (!_strnicmp (pe->sections[indexSec].Name, secname, 8)) {
            return indexSec;
            }
        }

    return 0xFFFFFFFF;
}


//
// Выводит информацию о заголовках.
//
void PrintPeHeaders (PeHeaders *pe) {


unsigned int i;

    char *buf[2] = {"a", "b"};

    printf ("**********  NT Header %d:\n", (unsigned int)pe->nthead - (unsigned int)pe->mem);
    printf ("File header %d:\n", (unsigned int)&pe->nthead->FileHeader - (unsigned int)pe->mem);
    printf ("\tMachine: %p\n", pe->nthead->FileHeader.Machine);
    printf ("\tSize optional header: %d\n", pe->nthead->FileHeader.SizeOfOptionalHeader);
    
    printf ("\tCharacteristics: %p ", pe->nthead->FileHeader.Characteristics);
    for (i = 0; i < 16; ++i){
        char *characteristics[] = { "IMAGE_FILE_RELOCS_STRIPPED",
                                    "IMAGE_FILE_EXECUTABLE_IMAGE", 
                                    "IMAGE_FILE_LINE_NUMS_STRIPPED",
                                    "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
                                    "IMAGE_FILE_AGGRESIVE_WS_TRIM",
                                    "IMAGE_FILE_LARGE_ADDRESS_AWARE",
                                    "",
                                    "IMAGE_FILE_BYTES_REVERSED_LO",
                                    "IMAGE_FILE_32BIT_MACHINE",
                                    "IMAGE_FILE_DEBUG_STRIPPED",
                                    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
                                    "IMAGE_FILE_NET_RUN_FROM_SWAP",
                                    "IMAGE_FILE_SYSTEM",
                                    "IMAGE_FILE_DLL",
                                    "IMAGE_FILE_UP_SYSTEM_ONLY",
                                    "IMAGE_FILE_BYTES_REVERSED_HI"};
        if (pe->nthead->FileHeader.Characteristics & (1 << i)){
            printf ("%s ", characteristics[i]);
            }
        }
    printf ("\n");


    printf ("Optional header: %d\n", (unsigned int)&pe->nthead->OptionalHeader - (unsigned int)pe->mem);
    printf ("\tLinkerVersion: %x %x\n", pe->nthead->OptionalHeader.MajorLinkerVersion, pe->nthead->OptionalHeader.MinorLinkerVersion);
    printf ("\tSizeOfCode: %x\n", pe->nthead->OptionalHeader.SizeOfCode);
    printf ("\tSizeOfInitializedData: %x\n", pe->nthead->OptionalHeader.SizeOfInitializedData);
    printf ("\tSizeOfUninitializedData: %x\n", pe->nthead->OptionalHeader.SizeOfUninitializedData);
    printf ("\tBaseOfCode: %x\n", pe->nthead->OptionalHeader.BaseOfCode);
    printf ("\tBaseOfData: %x\n", pe->nthead->OptionalHeader.BaseOfData);
    printf ("\tAddressOfEntryPoint: %x\n", pe->nthead->OptionalHeader.AddressOfEntryPoint);
    printf ("\tImageBase: %x\n", pe->nthead->OptionalHeader.ImageBase);
    printf ("\tSizeOfImage: %x\n", pe->nthead->OptionalHeader.SizeOfImage);
    printf ("\tSizeOfHeaders: %x\n", pe->nthead->OptionalHeader.SizeOfHeaders);
    printf ("\tSectionAlignment: %x\n", pe->nthead->OptionalHeader.SectionAlignment);
    printf ("\tFileAlignment: %x\n", pe->nthead->OptionalHeader.FileAlignment);
    printf ("\tMajorOperatingSystemVersion: %d\n", pe->nthead->OptionalHeader.MajorOperatingSystemVersion);
    printf ("\tMinorOperatingSystemVersion: %d\n", pe->nthead->OptionalHeader.MinorOperatingSystemVersion);
    printf ("\tCheckSum: %x\n", pe->nthead->OptionalHeader.CheckSum);
    printf ("\tSizeOfStackReserve: %x\n", pe->nthead->OptionalHeader.SizeOfStackReserve);
    printf ("\tSizeOfStackCommit: %x\n", pe->nthead->OptionalHeader.SizeOfStackCommit);
    printf ("\tSizeOfHeapReserve: %x\n", pe->nthead->OptionalHeader.SizeOfHeapReserve);
    printf ("\tSizeOfHeapCommit: %x\n", pe->nthead->OptionalHeader.SizeOfHeapCommit);

    {
    char *subsystems[] = {"UNKNOWN",
                         "NATIVE",
                         "WINDOWS_GUI",
                         "WINDOWS_CUI",
                         "OS2_CUI",
                         "POSIX_CUI",
                         "NATIVE_WINDOWS",
                         "WINDOWS_CE_GUI",
                         "EFI_APPLICATION",
                         "EFI_BOOT_SERVICE_DRIVER",
                         "EFI_RUNTIME_DRIVER",
                         "EFI_ROM",
                         "XBOX",
                         "WINDOWS_BOOT_APPLICATION"};
    printf ("\tSubsystem: %s\n", subsystems[pe->nthead->OptionalHeader.Subsystem]);
    }

    printf ("\tDllCharacteristics: (%x)", pe->nthead->OptionalHeader.DllCharacteristics);
    for (i = 0; i < 16; ++i) {
        char *dllchar[] = { "", "", "", "", "", "",
                            "DYNAMIC_BASE",
                            "FORCE_INTEGRITY",
                            "NX_COMPAT",
                            "NO_ISOLATION",
                            "NO_SEH",
                            "NO_BIND",
                            "",
                            "WDM_DRIVER",
                            "",
                            "TERMINAL_SERVER_AWARE"};
        if (pe->nthead->OptionalHeader.DllCharacteristics & (1 << i)) {
            printf ("%s ", dllchar[i]);
            }
        }
    printf ("\n\n");

    return;
}


//
// Выводит таблицу директорий.
//
void PrintDirectoryTable (PeHeaders *pe) {


    DWORD i;
    char *dirname[] = { "EXPORT",
                        "IMPORT",
                        "RESOURCE",
                        "EXCEPTION",
                        "SECURITY",
                        "BASERELOC",
                        "DEBUG",
                        "ARCHITECTURE",
                        "GLOBALPTR",
                        "TLS",
                        "LOAD_CONFIG",
                        "BOUND_IMPORT",
                        "IAT",
                        "DELAY_IMPORT",
                        "COM_DESCRIPTOR"};

    printf ("**********  Directories: %d\n", (unsigned int)pe->nthead->OptionalHeader.DataDirectory - (unsigned int)pe->mem);

    for (i = 0; i < 15; ++i) {
        printf ("%-16s%p\t%p\n", 
            dirname[i], 
            pe->nthead->OptionalHeader.DataDirectory[i].VirtualAddress, 
            pe->nthead->OptionalHeader.DataDirectory[i].Size);
        }
    printf ("\n");

    return;
}


//
// Выводит информацию о таблице импорта.
//
void PrintImportTable (PeHeaders *pe) {


IMAGE_IMPORT_DESCRIPTOR *imp;


    puts ("**********  Import Table:\n");

    // вывод имён функций в таблице импорта 
    imp = pe->impdir;
    while (!(imp->FirstThunk == 0 &&
           imp->Characteristics == 0 &&
           imp->ForwarderChain == 0 &&
           imp->Name == 0 &&
           imp->OriginalFirstThunk == 0 &&
           imp->TimeDateStamp == 0) ) {

        unsigned int *buf;
        unsigned int j;

        // вывод имени импортируемой библиотеки
        printf ("%s\n", (char*)(pe->mem + RvaToOffset (imp->Name, pe)));

        // указатель на массив OriginalFirstThunk
        buf = (unsigned int *)(pe->mem + RvaToOffset (imp->OriginalFirstThunk, pe));

        // цикл до первого нулевого элемента в массиве
        for (j = 0; buf[j]; ++j) {

            // если по ординалу
            if (buf[j] & 0x80000000){
                printf ("\tby ordinal %d\n", buf[j] & 0x0000FFFF);
                }
            // если по имени
            else {
				printf ("\t%s %p\n", (char*)(pe->mem + RvaToOffset(buf[j], pe) + 2), &((void**)imp->FirstThunk)[j]);
                }

            }
        ++imp;
        }

    return;
}


//
// Выводит таблицу секций.
//
void PrintSectionTable (PeHeaders *pe) {

DWORD i;

    printf ("**********  Sections Table\n\n");
    printf ("name      VirtAddr  VirtSize  RawAddr   RawSize   Character\n");
    for (i = 0; i < pe->countSec; ++i) {
        printf ("%-8s  ", &pe->sections[i].Name);
        printf ("%p  ", pe->sections[i].VirtualAddress);
        printf ("%p  ", pe->sections[i].Misc.VirtualSize);
        printf ("%p  ", pe->sections[i].PointerToRawData);
        printf ("%p  ", pe->sections[i].SizeOfRawData);
        printf ("%p\n", pe->sections[i].Characteristics);
        }
    printf ("\n");

    return;
}


//
// Выводит информацию о таблице экспорта.
//
void PrintExportTable (PeHeaders *pe) {

IMAGE_EXPORT_DIRECTORY *exp;
DWORD *functionsArray;
DWORD *namesArray;
WORD *nameOrdinalsArray;
DWORD i;

    if (!pe->expdir)
        return;

    exp = pe->expdir; //029E0400 

    puts ("**********  Export Table:\n");

    printf ("name: %s\n", pe->mem + RvaToOffset (exp->Name, pe));
    printf ("time: %p\n", exp->TimeDateStamp);
    printf ("char: %p\n", exp->Characteristics);
    printf ("base: %d\n", exp->Base);
    printf ("num fun: %d\n", exp->NumberOfFunctions);
    printf ("num names: %d\n", exp->NumberOfNames);


    // указатель на массив адресов функций
    functionsArray = (DWORD*) (pe->mem + RvaToOffset (exp->AddressOfFunctions, pe));

    // указатель на массив адресов имён функций
    namesArray = (DWORD*) (pe->mem + RvaToOffset (exp->AddressOfNames, pe));

    // указатель на массив ординалов именованных функций
    nameOrdinalsArray = (WORD*) (pe->mem + RvaToOffset (exp->AddressOfNameOrdinals, pe));

    for (i = 0; i < exp->NumberOfNames; ++i) {
        printf ("%d ", nameOrdinalsArray[i] + exp->Base);
        printf ("%s\t", pe->mem + RvaToOffset (namesArray[i], pe));
		printf ("%p\n", functionsArray[nameOrdinalsArray[i]]);
        }
    printf ("\n");

    return;
}


//
// Выводит одну строку шестнадцатиричных символов.
//
void PrintHexLine (unsigned char *line, unsigned int lineSize) {

unsigned int i;

    // вывод ASCII-символов
    for (i = 0; i < lineSize; ++i) {
        printf ("%02X ", line[i]);
        }

    printf ("  ");

    // вывод символов
    for (i = 0; i < lineSize; ++i) {

        if (isprint (line[i])) {
            printf ("%c", line[i]);
            }
        else {
            printf (" ");
            }

        }

    return;
}


//
// Выводит дамп памяти в шестнадцатиричном виде.
//
void PrintDump (
    unsigned char *memory, 
    unsigned int bytesFromMemoryCount, 
    unsigned bytesTotalCount, 
    unsigned int printAddress,
    unsigned int bytesPerLine,
    char *prefixName) {

unsigned int bytesIndex;
unsigned char *line = (unsigned char*) malloc (bytesPerLine);
unsigned int lineIndex = 0;

    for (bytesIndex = 0; bytesIndex < bytesTotalCount; ++bytesIndex) {

        if (bytesIndex % bytesPerLine == 0) {
            printf ("%s %p: ", prefixName, printAddress + bytesIndex);
            }

        if (bytesIndex < bytesFromMemoryCount) {
            line[lineIndex++] = memory[bytesIndex];
            }
        // если символы в памяти закончились - заполняем нулями
        else {
            line[lineIndex++] = 0;
            }

        // если конец очередной строки
        if ((bytesIndex + 1) % bytesPerLine == 0) {

            PrintHexLine (line, bytesPerLine);
            printf ("\n");

            lineIndex = 0;

            }
        }

    free (line);

    return;
}


//
// Выводит содержимое секции в файле.
//
void PrintSectionInFileDump (PeHeaders *pe, unsigned int sectionNumber, unsigned int bytesPerLine) {

IMAGE_SECTION_HEADER *sec = pe->sections + sectionNumber;

    //printf ("\tSection %s dump in file:\n", &sec->Name);

    PrintDump (
        (unsigned char*) pe->mem + sec->PointerToRawData, 
        sec->SizeOfRawData, 
        AlignToTop (sec->SizeOfRawData, pe->nthead->OptionalHeader.FileAlignment), 
        sec->PointerToRawData, 
        bytesPerLine,
        sec->Name);

    printf ("\n");

    return;
}


//
// Выводит содержимое всех секций в файле.
//
void PrintSectionsInFileDump (PeHeaders *pe, unsigned int bytesPerLine) {

DWORD i;

    for (i = 0; i < pe->countSec; ++i) {
        PrintSectionInFileDump (pe, i, bytesPerLine);
        }

    return;
}


//
// Выводит содержимое образа секции в памяти.
//
void PrintSectionInMemoryDump (PeHeaders *pe, unsigned int sectionNumber, unsigned int bytesPerLine) {

IMAGE_SECTION_HEADER *sec = pe->sections + sectionNumber;

    //printf ("\tSection %s dump in memory:\n", &sec->Name);

    PrintDump (
        (unsigned char*) pe->mem + sec->PointerToRawData, 
        min (sec->Misc.VirtualSize, sec->SizeOfRawData), 
        AlignToTop (sec->Misc.VirtualSize, pe->nthead->OptionalHeader.SectionAlignment), 
        sec->VirtualAddress + pe->nthead->OptionalHeader.ImageBase, 
        bytesPerLine,
        sec->Name);

    printf ("\n");

    return;
}


//
// Выводит образы всех секций в памяти.
//
void PrintSectionsInMemoryDump (PeHeaders *pe, unsigned int bytesPerLine) {

DWORD i;

    for (i = 0; i < pe->countSec; ++i) {
        PrintSectionInMemoryDump (pe, i, bytesPerLine);
        }

    return;
}


//
// Выводит содержимое заголовков в файле.
//
void PrintHeadersInFileDump (PeHeaders *pe, unsigned int bytesPerLine) {


    PrintDump (
        pe->mem,
        pe->nthead->OptionalHeader.SizeOfHeaders,
        pe->nthead->OptionalHeader.SizeOfHeaders,
        0,
        bytesPerLine,
        "hdr");

    return;
}


//
// Выводит содержимое заголовков в памяти.
//
void PrintHeadersInMemoryDump (PeHeaders *pe, unsigned int bytesPerLine) {


    PrintDump (
        pe->mem,
        pe->nthead->OptionalHeader.SizeOfHeaders,
        AlignToTop (pe->nthead->OptionalHeader.SizeOfHeaders, pe->nthead->OptionalHeader.SectionAlignment),
        pe->nthead->OptionalHeader.ImageBase,
        bytesPerLine,
        "hdr");

    return;
}


//
// Выводит дамп файла по секциям.
//
void PrintFileDump (PeHeaders *pe, unsigned int bytesPerLine) {


    PrintHeadersInFileDump (pe, bytesPerLine);

    PrintSectionsInFileDump (pe, bytesPerLine);

    return;
}


//
// Выводит дамп образа файла по секциям.
//
void PrintImageDump (PeHeaders *pe, unsigned int bytesPerLine) {


    PrintHeadersInMemoryDump (pe, bytesPerLine);

    PrintSectionsInMemoryDump (pe, bytesPerLine);

    return;
}


//
// Выводит дамп секции с именем secname в файле.
//
void PrintSectionInFileDumpByName (PeHeaders *pe, unsigned int bytesPerLine, char *secname) {

unsigned int indexSec = GetSectionIndexByName (pe, secname);

    if (indexSec == 0xFFFFFFFF)
        return;

    PrintSectionInFileDump (pe, indexSec, bytesPerLine);

    return;
}


//
// Выводит дамп секции с именем secname в памяти.
//
void PrintSectionInMemoryDumpByName (PeHeaders *pe, unsigned int bytesPerLine, char *secname) {

unsigned int indexSec = GetSectionIndexByName (pe, secname);

    if (indexSec == 0xFFFFFFFF)
        return;

    PrintSectionInMemoryDump (pe, indexSec, bytesPerLine);

    return;
}


//
// Выводит информацию о перемещаемых элементах.
//
void PrintBaseReloc (PeHeaders *pe) {

DWORD offset = 0;
IMAGE_BASE_RELOCATION *reloc;
char *relocType[] = {"IMAGE_REL_BASED_ABSOLUTE",
                     "IMAGE_REL_BASED_HIGH",
                     "IMAGE_REL_BASED_LOW",
                     "IMAGE_REL_BASED_HIGHLOW",
                     "IMAGE_REL_BASED_HIGHADJ",
                     "IMAGE_REL_BASED_MIPS_JMPADDR",
                     "", "", "",
                     "IMAGE_REL_BASED_IA64_IMM64",
                     "IMAGE_REL_BASED_DIR64"};
WORD *baseRelocOffset;

    if ((pe->nthead->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ||
        !pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
        !pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        return;

    reloc = (IMAGE_BASE_RELOCATION*) (pe->mem + RvaToOffset (pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pe));

    while (offset < pe->nthead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        unsigned int i;
        baseRelocOffset = (WORD*)((DWORD)reloc + sizeof(IMAGE_BASE_RELOCATION));
        for (i = 0; i < (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD); ++i) {
            printf ("%x\t%s\n", reloc->VirtualAddress + (baseRelocOffset[i] & 0x0FFF), 
                               relocType[baseRelocOffset[i] >> 12]);
            }
        offset += reloc->SizeOfBlock;
        reloc = (IMAGE_BASE_RELOCATION *) ((DWORD)reloc + reloc->SizeOfBlock);
        }

    return;
}
