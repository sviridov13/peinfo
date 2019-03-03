/*

Модуль peinfo_main.c.

Главный модуль программы peinfo 
отображения информации о PE-файле.

Маткин Илья Александрович   15.10.2012

*/

#include <windows.h>
#include <stdio.h>

#include "pe_parser.h"

//----------------------------------------


#define BYTES_PER_LINE  16

//----------------------------------------


void usage(void) {


    printf ("peinfo <filename> <opt> [<subopt>]\n");
    printf ("opt:\n"
            "\tfiledump\n"
            "\timagedump\n"
            "\theader\n"
            "\tsection\n"
            "\timport\n"
            "\texport\n"
            "\tsecfdump secname\n"
            "\tsecmdump secname\n"
            "\theadfdump\n"
            "\theadmdump\n"
            "\treloc\n");

    return;
}


int main (unsigned int argc, char *argv[], char *envp[]) {


    PeHeaders pe;

    if(argc < 3){
        usage();
        return 1;
        }

    if (!LoadPeFile (argv[1], &pe, 0)) {
    //if (!LoadPeFile ("C:\\Windows\\SysWOW64\\kernel32.dll", &pe, 0)) {
    //if (!LoadPeFile ("taskmgr.exe", &pe, 0)) {
        return 1;
        }

    if (!strcmp (argv[2], "filedump")) {
        PrintFileDump (&pe, BYTES_PER_LINE);
        }

    if (!strcmp (argv[2], "imagedump")) {
        PrintImageDump (&pe, BYTES_PER_LINE);
        }

    if (!strcmp (argv[2], "header")) {
        PrintPeHeaders (&pe);
        PrintDirectoryTable (&pe);
        }

    if (!strcmp (argv[2], "section")) {
        PrintSectionTable (&pe);
        }
	
    if (!strcmp (argv[2], "import")) {
        PrintImportTable (&pe);
        }

    if (!strcmp (argv[2], "export")) {
        PrintExportTable (&pe);
        }
	
    if (!strcmp (argv[2], "secfdump")) {
        if (argv[3])
            PrintSectionInFileDumpByName (&pe, BYTES_PER_LINE, argv[3]);
        else
            usage();
        }

    if (!strcmp (argv[2], "secmdump")) {
        if (argv[3])
            PrintSectionInMemoryDumpByName (&pe, BYTES_PER_LINE, argv[3]);
        else
            usage();
        }

    if (!strcmp (argv[2], "headfdump")) {
        PrintHeadersInFileDump (&pe, BYTES_PER_LINE);
        }

    if (!strcmp (argv[2], "headmdump")) {
        PrintHeadersInMemoryDump (&pe, BYTES_PER_LINE);
        }

    if (!strcmp (argv[2], "reloc")) {
        PrintBaseReloc (&pe);
        }


    // освобождаем все ресурсы
    UnmapViewOfFile (pe.mem);
    CloseHandle (pe.fd);
    CloseHandle (pe.mapd);

    return 0;
}
