;
; ���� pe.inc ������������ ���� ������ pe.asm
;
; ������ ���� ������������� 21.11.2012
;


include c:\masm32\include\windows.inc

PeHeaders struct

    filename DWORD      ?   ;��� �����

    fd          HANDLE  ?   ;����� ��������� �����
    mapd        HANDLE  ?   ;����� �������� ��������
    mem	        DWORD   ?   ;��������� �� ������ ���������������� �����
    filesize    DWORD   ?   ;������ ��������������� ����� �����

    doshead     DWORD   ?   ;��������� �� DOS ���������
    nthead      DWORD   ?   ;��������� �� NT ���������

    impdir      DWORD   ?   ;��������� �� ������ ������������ ������� �������
    sizeImpdir  DWORD   ?   ;������ ������� �������
    countImpdes DWORD   ?   ;���������� ��������� � ������� �������

    expdir      DWORD   ?   ;��������� �� ������� ��������
    sizeExpdir  DWORD   ?   ;������ ������� ��������

    sections    DWORD   ?   ;��������� �� ������� ������ (�� ������ �������)
    countSec    DWORD   ?   ;���������� ������

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