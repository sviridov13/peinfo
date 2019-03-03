;
; Модуль peinfo_main.asm.
;
; Маткин Илья Александрович 21.11.2012
;

.686
.model flat, stdcall
option casemap:none

include c:\masm32\include\msvcrt.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc

include Strings.mac
include pe_parser.inc

printf proto c :dword, :vararg
strcmp proto c :dword, :vararg
LoadPeFile PROTO STDCALL :DWORD,:DWORD, :DWORD
;PrintPeHeaders proto stdcall :DWORD
PrintDirectoryTable proto stdcall :DWORD
PrintPeHeaders PROTO STDCALL :DWORD

.data


.data?

.const
format db "%d",13,10,0
ok db "OK",0
str1 db	"peinfo <filename> <opt> [<subopt>]",13,10,0
str2 db "opt:",13,10,0
str3 db 9,"filedump",13,10,0
str4 db	9,"imagedump",13,10,0
str5 db	9,"header",13,10,0
str6 db 9,"section",13,10,0
str7 db 9,"import",13,10,0
str8 db 9,"export",13,10,0
str9 db 9,"secfdump secname",13,10,0
str10 db 9,"secmdump secname",13,10,0
str11 db 9,"headfdump",13,10,0
str12 db 9,"headmdump",13,10,0
str13 db 9,"reloc",13,10,0

BYTES_PER_LINE = 16

.code


print_array proc c arg:DWORD

    local arrayPointer:DWORD
    local i:DWORD

    mov ebx, [arg]
	mov ebx, [ebx]
	mov [arrayPointer], ebx
	mov [i], 0
	.while [arrayPointer] != 0
	    invoke crt_printf, $CTA0 ("%s\n"), [arrayPointer]
	    invoke strcmp, [arrayPointer], $CTA0 ("import")
	    .if !eax
	        invoke crt_puts, $CTA0 ("find import\n")
	    .endif
	    add [i], 4
	    mov ecx, [i]
	    mov ebx, [arg]
	    mov ebx, [ebx + ecx]
	    mov [arrayPointer], ebx
	.endw

    ret
    
print_array endp

usage proc stdcall

	invoke printf, offset str1
	invoke printf, offset str2
    invoke printf, offset str3
    invoke printf, offset str4
    invoke printf, offset str5
    invoke printf, offset str6
    invoke printf, offset str7
    invoke printf, offset str8
    invoke printf, offset str9
    invoke printf, offset str10
    invoke printf, offset str11
    invoke printf, offset str12
    invoke printf, offset str13

	ret
	
usage endp

main proc c argc:DWORD, argv:DWORD, envp:DWORD


    local pe :PeHeaders

	;invoke MessageBox, 0, $CTA0 ("Test"), $CTA0 ("Message"), 0

	;invoke print_array, argv
	;invoke print_array, envp
	
	mov eax, [argc]
	.if eax < 3
		invoke usage
		mov eax, 1
		ret
	.endif
	
	mov ebx, [argv]
	invoke LoadPeFile, [ebx + 4], addr pe, 0
	
	.if eax == 0
		mov eax, 1
		ret
	.endif
	
	mov ebx, [ebx + 8]
	
	invoke strcmp, ebx, $CTA0("filedump")
	.if eax == 0
		invoke PrintFileDump, addr pe, BYTES_PER_LINE
	.endif
	
	invoke strcmp, ebx, $CTA0("imagedump")
	.if eax == 0
		invoke PrintImageDump, addr pe, BYTES_PER_LINE
	.endif
	
	invoke strcmp, ebx, $CTA0("header")
	.if eax == 0
		invoke PrintPeHeaders, addr pe
		invoke PrintDirectoryTable, addr pe
	.endif
	
	
	
	invoke strcmp, ebx, $CTA0("import")
	.if eax == 0
		invoke PrintImportTable, addr pe
	.endif
	
	invoke strcmp, ebx, $CTA0("section")
	.if eax == 0
		invoke PrintSectionTable, addr pe
	.endif
	
	invoke strcmp, ebx, $CTA0("export")
	.if eax == 0
		invoke PrintExportTable, addr pe
	.endif
	
	invoke strcmp, ebx, $CTA0("secfdump")
	.if eax == 0
		mov ecx, [argv]
		mov ecx, dword ptr [ecx + 12]
		.if ecx
			invoke PrintSectionInFileDumpByName, addr pe, BYTES_PER_LINE, ecx
		.else
			invoke usage
		.endif
	.endif
	
	invoke strcmp, ebx, $CTA0("secmdump")
	.if eax == 0
		mov ecx, [argv]
		mov ecx, dword ptr [ecx + 12]
		.if ecx
			invoke PrintSectionInMemoryDumpByName, addr pe, BYTES_PER_LINE, ecx
		.else
			invoke usage
		.endif
	.endif
	
	invoke strcmp, ebx, $CTA0("headfdump")
	.if eax == 0
		invoke PrintHeadersInFileDump, addr pe, BYTES_PER_LINE
	.endif
	
	invoke strcmp, ebx, $CTA0("headmdump")
	.if eax == 0
		invoke PrintHeadersInMemoryDump, addr pe, BYTES_PER_LINE
	.endif
	
	invoke strcmp, ebx, $CTA0("reloc")
	.if eax == 0
		invoke PrintBaseReloc, addr pe
	.endif
	

	mov eax, 0
	ret 12

main endp


end
