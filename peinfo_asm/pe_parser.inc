;
; Файл pe.inc заголовочный файл модуля pe.asm
;
; Маткин Илья Александрович 21.11.2012
;


include c:\masm32\include\windows.inc

PeHeaders struct

    filename DWORD      ?   ;имя файла

    fd          HANDLE  ?   ;хендл открытого файла
    mapd        HANDLE  ?   ;хендл файловой проекции
    mem	        DWORD   ?   ;указатель на память спроецированного файла
    filesize    DWORD   ?   ;размер спроецированной части файла

    doshead     DWORD   ?   ;указатель на DOS заголовок
    nthead      DWORD   ?   ;указатель на NT заголовок

    impdir      DWORD   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      DWORD   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    DWORD   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций

PeHeaders ends
	

PrintPeHeaders PROTO STDCALL :dword
LoadPeFile PROTO STDCALL :DWORD,:DWORD, :DWORD
UnloadPeFile PROTO STDCALL :DWORD
RvaToOffset proto stdcall :DWORD, :DWORD
AlignToTop proto stdcall :DWORD, :DWORD
AlignToBottom proto stdcall :DWORD, :DWORD
;PrintPeHeaders PROTO STDCALL :DWORD
PrintDirectoryTable PROTO STDCALL :DWORD
PrintImportTable proto stdcall :DWORD
PrintSectionTable proto stdcall :DWORD
PrintExportTable proto stdcall :DWORD
PrintSectionInFileDumpByName proto stdcall :DWORD, :DWORD, :DWORD
PrintSectionInMemoryDumpByName proto stdcall :DWORD, :DWORD, :DWORD
PrintFileDump proto stdcall :DWORD, :DWORD
PrintImageDump proto stdcall :DWORD, :DWORD
PrintHeadersInFileDump proto stdcall :DWORD, :DWORD
PrintHeadersInMemoryDump proto stdcall :DWORD, :DWORD
PrintBaseReloc proto stdcall :DWORD