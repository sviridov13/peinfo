;
; Модуль pe.asm
;
; Маткин Илья Александрович 21.11.2012
;

.686
.model flat, stdcall
option casemap:none


include c:\masm32\include\kernel32.inc
include c:\masm32\include\windows.inc
;include c:\masm32\include\msvcrt.inc
;c:\masm32\lib\msvcrt.lib

include pe_parser.inc
include system.inc
include Strings.mac
;libcmt.lib 
printf proto c :VARARG

_strnicmp proto c :DWORD,:DWORD,:DWORD
puts proto c :DWORD
isprint proto c :BYTE
malloc proto c :DWORD
free proto c :DWORD


.data

.data?

.const

.code


ParsePeFileHeader proc stdcall uses ebx edx mem:DWORD, pe:DWORD

    mov ebx, [pe]
    assume ebx: ptr PeHeaders
    

    ret

ParsePeFileHeader endp



LoadPeFile proc stdcall uses ebx filename:DWORD, pe:DWORD, filesize:DWORD

    mov ebx, [pe]
    assume ebx: ptr PeHeaders

    mov eax, [filename]
    mov [ebx].filename, eax
    
    invoke CreateFile, filename, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov [ebx].fd, eax
    .if [ebx].fd == INVALID_HANDLE_VALUE
        ;invoke PrintLastErrorMessage
        invoke puts, $CTA0 ("Error open file\n")
        xor eax, eax
        ret
    .endif
    
    .if [filesize]
        mov eax, [filesize]
        mov [ebx].filesize, eax
    .else
        invoke GetFileSize, [ebx].fd, 0
        mov [ebx].filesize, eax
    .endif
    
    invoke CreateFileMapping, [ebx].fd, 0, PAGE_READONLY, 0, [ebx].filesize, 0
    mov [ebx].mapd, eax
    .if [ebx].mapd == 0
        invoke CloseHandle, [ebx].fd
        invoke puts, $CTA0 ("Error create fie mapping\n")
        xor eax, eax
        ret
    .endif
    
    invoke MapViewOfFile, [ebx].mapd, FILE_MAP_READ, 0, 0, 0
    mov [ebx].mem, eax
    .if [ebx].mem == 0
        invoke CloseHandle, [ebx].mapd
        invoke CloseHandle, [ebx].fd
        invoke puts, $CTA0 ("Error mapping file\n")
        xor eax, eax
        ret
    .endif

    ;invoke ParsePeFileHeader, [ebx].mem, [pe]
    
    mov eax, [ebx].mem
    mov [ebx].doshead, eax
    
    mov eax, [ebx].doshead
    movzx eax, [eax].IMAGE_DOS_HEADER.e_magic
    .if eax != IMAGE_DOS_SIGNATURE
		invoke UnmapViewOfFile, [ebx].mem
		invoke CloseHandle, [ebx].mapd
        invoke CloseHandle, [ebx].fd
        invoke puts, $CTA0 ("Error DOS signature\n")
        xor eax, eax
        ret
    .endif
    
    mov eax, [ebx].mem
    mov ecx, [ebx].doshead
    mov ecx, [ecx].IMAGE_DOS_HEADER.e_lfanew
    add eax, ecx
    mov [ebx].nthead, eax
	mov eax, [eax].IMAGE_NT_HEADERS.Signature
	.if eax != IMAGE_NT_SIGNATURE
		invoke UnmapViewOfFile, [ebx].mem
		invoke CloseHandle, [ebx].mapd
        invoke CloseHandle, [ebx].fd
        invoke puts, $CTA0 ("Error NT signature\n")
        xor eax, eax
        ret
    .endif
    
    mov edx, [ebx].nthead
    add edx, 24
    mov eax, [ebx].nthead
    add eax, 4
    movzx eax, [eax].IMAGE_FILE_HEADER.SizeOfOptionalHeader
    add edx, eax
    mov [ebx].sections, edx
    
    mov eax, [ebx].nthead
    add eax, 4
    movzx eax, [eax].IMAGE_FILE_HEADER.NumberOfSections
    mov [ebx].countSec, eax
    
    mov edx, [ebx].nthead
    add edx, 24 + 96 ;OptionalHeader.DataDirectory
    mov eax, IMAGE_DIRECTORY_ENTRY_EXPORT
    shl eax, 3
    mov ecx, dword ptr [edx + eax] ;DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    
    .if ecx
		invoke RvaToOffset, ecx, ebx
		mov ecx, [ebx].mem
		add ecx, eax
		mov [ebx].expdir, ecx
		
		mov edx, [ebx].nthead
		add edx, 24 + 96
		mov eax, IMAGE_DIRECTORY_ENTRY_EXPORT
		shl eax, 3
		mov ecx, dword ptr [edx + eax + 4]
		mov [ebx].sizeExpdir, ecx
	.else
		mov [ebx].expdir, 0
		mov [ebx].sizeExpdir, 0
	.endif
	
	mov edx, [ebx].nthead
    add edx, 24 + 96 ;OptionalHeader.DataDirectory
    mov eax, IMAGE_DIRECTORY_ENTRY_IMPORT
    shl eax, 3
    mov ecx, dword ptr [edx + eax] ;DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    
    .if ecx
		invoke RvaToOffset, ecx, ebx
		mov ecx, [ebx].mem
		add ecx, eax
		mov [ebx].impdir, ecx
		
		mov edx, [ebx].nthead
		add edx, 24 + 96
		mov eax, IMAGE_DIRECTORY_ENTRY_IMPORT
		shl eax, 3
		mov ecx, dword ptr [edx + eax + 4]
		mov [ebx].sizeImpdir, ecx
	.else
		mov [ebx].impdir, 0
		mov [ebx].sizeImpdir, 0
	.endif
	
    mov eax, 1
    ret    

LoadPeFile endp

UnloadPeFile proc stdcall pe:DWORD

	mov eax, [pe]
	invoke UnmapViewOfFile, [eax].PeHeaders.mem
	invoke CloseHandle, [eax].PeHeaders.fd
	invoke CloseHandle, [eax].PeHeaders.mapd
	
	ret

UnloadPeFile endp

RvaToOffset proc stdcall uses ebx rva:DWORD, pe:DWORD

	local i:DWORD
	local sections:DWORD
	local NumberSections:DWORD
	
	mov eax, [pe]
	mov eax, [eax].PeHeaders.sections
	mov [sections], eax
	
	mov eax, [pe]
	mov eax, [eax].PeHeaders.countSec
	mov [NumberSections], eax
	
	mov eax, [pe]
	mov eax, [eax].PeHeaders.nthead
	lea eax, [eax].IMAGE_NT_HEADERS.OptionalHeader
	mov eax, [eax].IMAGE_OPTIONAL_HEADER.SizeOfImage
	
	.if [rva] > eax
		mov eax, 0
		ret
	.endif
	
	mov [i], 0
	mov ecx, [i]
	.while ecx < [NumberSections]
		
		imul ecx, 40
		mov eax, [sections]
		add eax, ecx 
		mov eax, [eax].IMAGE_SECTION_HEADER.VirtualAddress
		
		mov ecx, [i]
		imul ecx, 40
		mov edx, [sections]
		add edx, ecx
		mov edx, [edx].IMAGE_SECTION_HEADER.Misc
		;mov edx, [edx + 4]
		add edx, eax
		
		.if [rva] >= eax
			.if [rva] <= edx
			
				mov edx, [sections]
				mov ecx, [i]
				push edx
				imul ecx, 40
				pop edx
				add edx, ecx
				mov edx, [edx].IMAGE_SECTION_HEADER.PointerToRawData
				
				mov ebx, [rva]
				sub ebx, eax
				add ebx, edx
				
				mov eax, ebx
				ret
			.endif
		.endif 
		
		inc [i]
		mov ecx, [i]
	.endw
		
	xor eax, eax
	ret
RvaToOffset endp

AlignToTop proc stdcall value:DWORD, align1:DWORD
	
	local mask1:DWORD
	
	mov eax, [align1]
	dec eax
	not eax
	
	mov [mask1], eax
	
	mov eax, [value]
	add eax, [align1]
	dec eax
	and eax, [mask1]
	
	ret
AlignToTop endp

AlignToBottom proc stdcall value:DWORD, align1:DWORD

	local mask1:DWORD
	
	mov eax, [align1]
	dec eax
	not eax
	mov [mask1], eax
	
	mov eax, [value]
	and eax, [mask1]
	
	ret
AlignToBottom endp

GetSectionIndexByName proc stdcall pe:DWORD, secname:DWORD

	local indexSec:DWORD
	local cSec:DWORD
	
	mov eax, [pe]
	mov eax, [eax].PeHeaders.countSec
	mov [cSec], eax
	
	mov [indexSec], 0
	mov ecx, [indexSec]
	.while ecx < [cSec]
		
		
		imul ecx, 40
		mov eax, [pe]
		mov eax, [eax].PeHeaders.sections
		add eax, ecx
		
		invoke _strnicmp, eax, [secname], 8
		
		.if eax == 0
			mov eax, [indexSec]
			ret
		.endif
		
		
		inc [indexSec]
		mov ecx, [indexSec]
	.endw 
	
	
	mov eax, 0FFFFFFFFh
	ret
GetSectionIndexByName endp

PrintPeHeaders proc stdcall uses ebx pe:DWORD

	local i:DWORD
	local buf[2]:DWORD
	local characteristics[16]:DWORD
	local subsystems[14]:DWORD
	local dllchar[16]:DWORD
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	mov eax, [pe]
	mov eax, [eax].PeHeaders.mem
	sub edx, eax
	invoke printf, $CTA0("***********  NT Header %d:\n"), edx
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	;mov edx, dword ptr [edx].IMAGE_NT_HEADERS.FileHeader
	;mov edx, [edx]
	add edx, 4
	mov eax, [pe]
	mov eax, [eax].PeHeaders.mem
	sub edx, eax
	invoke printf, $CTA0("File header: %d\n"), edx
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	;mov edx, dword ptr [edx].IMAGE_NT_HEADERS.FileHeader
	add edx, 4
	mov dx, [edx].IMAGE_FILE_HEADER.Machine
	invoke printf, $CTA0("\tMachine: %p\n"), dx
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	;mov edx, dword ptr [edx].IMAGE_NT_HEADERS.FileHeader
	add edx, 4
	mov dx, [edx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
	invoke printf, $CTA0("\tSize optional header: %d\n"), dx
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	;mov edx, dword ptr [edx].IMAGE_NT_HEADERS.FileHeader
	add edx, 4
	mov dx, [edx].IMAGE_FILE_HEADER.Characteristics
	invoke printf, $CTA0("\tCharacteristics: %p "), dx
	
	
	lea eax, [characteristics]
	mov [eax+0], $CTA0("IMAGE_FILE_RELOCS_STRIPPED")
	mov [eax+4], $CTA0("IMAGE_FILE_EXECUTABLE_IMAGE")
	mov [eax+8], $CTA0("IMAGE_FILE_LINE_NUMS_STRIPPED")
	mov [eax+12], $CTA0("IMAGE_FILE_LOCAL_SYMS_STRIPPED")
	mov [eax+16], $CTA0("IMAGE_FILE_AGGRESIVE_WS_TRIM")
	mov [eax+20], $CTA0("IMAGE_FILE_LARGE_ADDRESS_AWARE")
	mov [eax+24], $CTA0("")
	mov [eax+28], $CTA0("IMAGE_FILE_BYTES_REVERSED_LO")
	mov [eax+32], $CTA0("IMAGE_FILE_32BIT_MACHINE")
	mov [eax+36], $CTA0("IMAGE_FILE_DEBUG_STRIPPED")
	mov [eax+40], $CTA0("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP")
	mov [eax+44], $CTA0("IMAGE_FILE_NET_RUN_FROM_SWAP")
	mov [eax+48], $CTA0("IMAGE_FILE_SYSTEM")
	mov [eax+52], $CTA0("IMAGE_FILE_DLL")
	mov [eax+56], $CTA0("IMAGE_FILE_UP_SYSTEM_ONLY")
	mov [eax+60], $CTA0("IMAGE_FILE_BYTES_REVERSED_HI")

	mov [i], 0
	mov ecx, [i]
	
	mov ebx, [pe]
	mov ebx, [ebx].PeHeaders.nthead
	;mov ebx, dword ptr [ebx + 4] ; .IMAGE_NT_HEADERS.FileHeader
	add ebx, 4
	movzx ebx, word ptr [ebx + 18] ;.IMAGE_FILE_HEADER.Characteristics
		
	.while ecx < 16
		mov eax, 1
		shl eax, cl
		
		and eax, ebx
		.if eax != 0
			shl ecx, 2
			lea eax, characteristics
			mov eax, [eax + ecx]
			invoke printf, $CTA0("%s "), eax
		.endif
		
		inc [i]
		mov ecx, [i]
	.endw
	invoke printf, $CTA0("\n")
	
	mov ebx, [pe]
	mov ebx, [ebx].PeHeaders.nthead
	;lea ebx, [ebx + 8] ;.IMAGE_NT_HEADERS.OptionalHeader
	add ebx, 24
	
	mov edx, ebx
	mov eax, [pe]
	mov eax, [eax].PeHeaders.mem
	sub edx, eax
	invoke printf, $CTA0("Optional header: %d\n"), edx
	
	movzx edx, byte ptr [ebx + 2] ;.IMAGE_OPTIONAL_HEADER.MajorLinkerVersion
	movzx ecx, byte ptr [ebx + 3] ;.IMAGE_OPTIONAL_HEADER.MinorLinkerVersion
	invoke printf, $CTA0("\tLinkerVersion: %x %x\n"), edx, ecx
	
	mov edx, dword ptr [ebx + 4] ;.IMAGE_OPTIONAL_HEADER.SizeOfCode
	invoke printf, $CTA0("\tSizeOfCode: %x\n"), edx
	mov edx, dword ptr [ebx + 8] ;.IMAGE_OPTIONAL_HEADER.SizeOfInitializedData
	invoke printf, $CTA0("\tSizeOfInitializedData: %x\n"), edx
	mov edx, dword ptr [ebx + 12] ;.IMAGE_OPTIONAL_HEADER.SizeOfUninitializedData
	invoke printf, $CTA0("\tSizeOfUninitializedData: %x\n"), edx
	mov edx, dword ptr [ebx + 20] ;.IMAGE_OPTIONAL_HEADER.BaseOfCode
	invoke printf, $CTA0("\tBaseOfCode: %x\n"), edx
	mov edx, dword ptr [ebx + 24] ;.IMAGE_OPTIONAL_HEADER.BaseOfData
	invoke printf, $CTA0("\tBaseOfData: %x\n"), edx
	mov edx, dword ptr [ebx + 16] ;.IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint
	invoke printf, $CTA0("\tAddressOfEntryPoint: %x\n"), edx
	mov edx, dword ptr [ebx + 28] ;.IMAGE_OPTIONAL_HEADER.ImageBase
	invoke printf, $CTA0("\tImageBase: %x\n"), edx
	mov edx, dword ptr [ebx + 56] ;.IMAGE_OPTIONAL_HEADER.SizeOfImage
	invoke printf, $CTA0("\tSizeOfImage: %x\n"), edx
	mov edx, dword ptr [ebx + 60] ;.IMAGE_OPTIONAL_HEADER.SizeOfHeaders
	invoke printf, $CTA0("\tSizeOfHeaders: %x\n"), edx
	mov edx, dword ptr [ebx + 32] ;.IMAGE_OPTIONAL_HEADER.SectionAlignment
	invoke printf, $CTA0("\tSectionAlignment: %x\n"), edx
	mov edx, dword ptr [ebx + 36] ;.IMAGE_OPTIONAL_HEADER.FileAlignment
	invoke printf, $CTA0("\tFileAlignment: %x\n"), edx
	movzx edx, word ptr [ebx + 40] ;.IMAGE_OPTIONAL_HEADER.MajorOperatingSystemVersion
	invoke printf, $CTA0("\tMajorOperatingSystemVersion: %d\n"), edx
	movzx edx, word ptr [ebx + 42] ;.IMAGE_OPTIONAL_HEADER.MinorOperatingSystemVersion
	invoke printf, $CTA0("\tMinorOperatingSystemVersion: %d\n"), edx
	mov edx, dword ptr [ebx + 64] ;.IMAGE_OPTIONAL_HEADER.CheckSum
	invoke printf, $CTA0("\tCheckSum: %x\n"), edx
	mov edx, dword ptr [ebx + 72] ;.IMAGE_OPTIONAL_HEADER.SizeOfStackReserve
	invoke printf, $CTA0("\tSizeOfStackReserve: %x\n"), edx
	mov edx, dword ptr [ebx + 76] ;.IMAGE_OPTIONAL_HEADER.SizeOfStackCommit
	invoke printf, $CTA0("\tSizeOfStackCommit: %x\n"), edx
	mov edx, dword ptr [ebx + 80] ;.IMAGE_OPTIONAL_HEADER.SizeOfHeapReserve
	invoke printf, $CTA0("\tSizeOfHeapReserve: %x\n"), edx
	mov edx, dword ptr [ebx + 84] ;.IMAGE_OPTIONAL_HEADER.SizeOfHeapCommit
	invoke printf, $CTA0("\tSizeOfHeapCommit: %x\n"), edx
	
	lea eax, [subsystems]
	mov [eax+0], $CTA0("UNKNOWN")
	mov [eax+4], $CTA0("NATIVE")
	mov [eax+8], $CTA0("WINDOWS_GUI")
	mov [eax+12], $CTA0("WINDOWS_CUI")
	mov [eax+16], $CTA0("OS2_CUI")
	mov [eax+20], $CTA0("POSIX_CUI")
	mov [eax+24], $CTA0("NATIVE_WINDOWS")
	mov [eax+28], $CTA0("WINDOWS_CE_GUI")
	mov [eax+32], $CTA0("EFI_APPLICATION")
	mov [eax+36], $CTA0("EFI_BOOT_SERVICE_DRIVER")
	mov [eax+40], $CTA0("EFI_RUNTIME_DRIVER")
	mov [eax+44], $CTA0("EFI_ROM")
	mov [eax+48], $CTA0("XBOX")
	mov [eax+52], $CTA0("WINDOWS_BOOT_APPLICATION")
	
	movzx edx, word ptr [ebx + 68] ;.IMAGE_OPTIONAL_HEADER.Subsystem
	shl edx, 2
	mov eax, [eax + edx]
	invoke printf, $CTA0("\tSubsystem: %s\n"), eax
	
	movzx edx, word ptr [ebx + 70] ;.IMAGE_OPTIONAL_HEADER.DllCharacteristics
	invoke printf, $CTA0("\tDllCharacteristics: (%x)"), edx
	
	lea eax, [dllchar]
	mov [eax+0], $CTA0("")
	mov [eax+4], $CTA0("")
	mov [eax+8], $CTA0("")
	mov [eax+12], $CTA0("")
	mov [eax+16], $CTA0("")
	mov [eax+20], $CTA0("")
	mov [eax+24], $CTA0("DYNAMIC_BASE")
	mov [eax+28], $CTA0("FORCE_INTEGRITY")
	mov [eax+32], $CTA0("NX_COMPAT")
	mov [eax+36], $CTA0("NO_ISOLATION")
	mov [eax+40], $CTA0("NO_SEH")
	mov [eax+44], $CTA0("NO_BIND")
	mov [eax+48], $CTA0("")
	mov [eax+52], $CTA0("WDM_DRIVER")
	mov [eax+56], $CTA0("")
	mov [eax+60], $CTA0("TERMINAL_SERVER_AWARE")
	
	mov [i], 0
	mov ecx, [i]
	
	movzx ebx, word ptr [ebx + 70] ;.IMAGE_OPTIONAL_HEADER.DllCharacteristics
	.while ecx < 16
		mov eax, 1
		shl eax, cl
		
		and eax, ebx
		.if eax != 0
			shl ecx, 2
			lea eax, dllchar
			mov eax, [eax + ecx]
			invoke printf, $CTA0("%s "), eax
		.endif
		
		inc [i]
		mov ecx, [i]
	.endw
	invoke printf, $CTA0("\n\n")

	ret
PrintPeHeaders endp

PrintDirectoryTable proc stdcall uses ebx pe:DWORD

	local i:DWORD
	local dirname[15]:DWORD
	
	lea eax, dirname
	mov [eax+0], $CTA0("EXPORT")
	mov [eax+4], $CTA0("IMPORT")
	mov [eax+8], $CTA0("RESOURCE")
	mov [eax+12], $CTA0("EXCEPTION")
	mov [eax+16], $CTA0("SECURITY")
	mov [eax+20], $CTA0("BASERELOC")
	mov [eax+24], $CTA0("DEBUG")
	mov [eax+28], $CTA0("ARCHITECTURE")
	mov [eax+32], $CTA0("GLOBALPTR")
	mov [eax+36], $CTA0("TLS")
	mov [eax+40], $CTA0("LOAD_CONFIG")
	mov [eax+44], $CTA0("BOUND_IMPORT")
	mov [eax+48], $CTA0("IAT")
	mov [eax+52], $CTA0("DELAY_IMPORT")
	mov [eax+56], $CTA0("COM_DESCRIPTOR")
	
	mov edx, [pe]
	mov edx, [edx].PeHeaders.nthead
	;lea edx, [edx].IMAGE_NT_HEADERS.OptionalHeader
	add edx, 24 + 96
	;mov edx, [edx].IMAGE_OPTIONAL_HEADER.DataDirectory
	;add edx, 96
	mov eax, [pe]
	mov eax, [eax].PeHeaders.mem
	sub edx, eax
	invoke printf, $CTA0("**********  Directories: %d\n"), edx
	
	mov ebx, [pe]
	mov ebx, [ebx].PeHeaders.nthead
	;lea ebx, [ebx + 8] ;.IMAGE_NT_HEADERS.OptionalHeader
	;mov ebx, dword ptr [ebx + 96] ;.IMAGE_OPTIONAL_HEADER.DataDirectory
	add ebx, 24 + 96
	
	mov [i], 0
	mov ecx, [i]
	
	.while ecx < 15
		lea edx, [dirname]
		shl ecx, 2
		mov edx, dword ptr [edx + ecx]
		mov ecx, [i]
		shl ecx, 3
		invoke printf, $CTA0("%-16s%p\t%p\n"), edx, [ebx + ecx], [ebx + ecx + 4]
		;.IMAGE_DATA_DIRECTORY.VirtualAddress
		;.IMAGE_DATA_DIRECTORY.Size
		inc [i]
		mov ecx, [i]
	.endw
						
	invoke printf, $CTA0("\n")
	
	ret
PrintDirectoryTable endp
	
PrintImportTable proc stdcall uses ebx pe:DWORD

	local imp:DWORD
	local buf:DWORD
	local j:DWORD
	
	invoke puts, $CTA0("**********  Import Table:\n")
	
	mov ebx, [pe]
	mov eax, [ebx].PeHeaders.impdir
	mov [imp], eax
	
	.while 1
	
	;(!([eax + 16] == 0 && [eax + 8] == 0 && [eax] == 0 && [eax + 4] == 0 && [eax + 12] == 0))
		mov ecx, dword ptr [eax]
		.if ecx == 0
		mov ecx, dword ptr [eax + 4]
		.if ecx == 0
		mov ecx, dword ptr [eax + 8]
		.if ecx == 0
		mov ecx, dword ptr [eax + 12]
		.if ecx == 0
		mov ecx, dword ptr [eax + 16]
		.if ecx == 0
			.break
		.endif
		.endif
		.endif
		.endif
		.endif
		
		
		
		mov edx, [imp]
		mov edx, dword ptr [edx + 12]
		invoke RvaToOffset, edx, ebx
		mov ecx, [ebx].PeHeaders.mem
		add ecx, eax
		invoke printf, $CTA0("%s\n"), ecx
		
		mov edx, [imp]
		mov edx, dword ptr [edx]
		invoke RvaToOffset, edx, ebx
		mov ecx, [ebx].PeHeaders.mem
		add ecx, eax
		
		mov [buf], ecx
		
		mov [j], 0
		
		mov eax, [buf]
		mov ecx, [j]
		shl ecx, 2
		mov ecx, dword ptr [eax + ecx] ;buf[j]
		
		.while ecx
			
			mov edx, ecx
			and edx, 80000000h
			
			.if edx
			
				mov edx, ecx
				and edx, 0000FFFFh
				invoke printf, $CTA0("\tby ordinal %d\n"), edx
				
			.else
				
				invoke RvaToOffset, ecx, ebx
				mov ecx, [ebx].PeHeaders.mem
				add eax, ecx
				add eax, 2
				;mov ecx, eax
				
				mov edx, [imp]
				;mov edx, dword ptr [edx + 16] ;FirstThunk
				mov ecx, [j]
				shl ecx, 2
				mov edx, dword ptr [edx + ecx + 16] ;FirstThunk[j]
				mov ecx, eax
				
				invoke printf, $CTA0("\t%s %p\n"), ecx, edx
						
			.endif
			
			inc [j]
			mov eax, [buf]
			mov ecx, [j]
			shl ecx, 2
			mov ecx, dword ptr [eax + ecx] ;buf[j]
			
		.endw
		 
		 
		mov eax, [imp]
		add eax, 20
		mov [imp], eax
		
		mov ebx, [pe]
		mov eax, [imp]
		
	.endw
	
	ret

PrintImportTable endp

PrintSectionTable proc stdcall uses ebx pe:DWORD

	local i:DWORD
	local csec:DWORD

	invoke printf, $CTA0("**********  Sections Table\n\n")
	invoke printf, $CTA0("name      VirtAddr  VirtSize  RawAddr   RawSize   Character\n")
	
	mov ebx, [pe]
	mov eax, [ebx].PeHeaders.countSec
	mov [csec], eax
	
	mov [i], 0
	mov ecx, [i]
	mov ebx, [ebx].PeHeaders.sections
	.while ecx < [csec]
	
		lea edx, [ebx]
		invoke printf, $CTA0("%-8s  "), addr [ebx]
		invoke printf, $CTA0("%p  "), dword ptr [ebx + 12]
		invoke printf, $CTA0("%p  "), dword ptr [ebx + 8]
		invoke printf, $CTA0("%p  "), dword ptr [ebx + 20]
		invoke printf, $CTA0("%p  "), dword ptr [ebx + 16]
		invoke printf, $CTA0("%p\n"), dword ptr [ebx + 36]
		
		add ebx, 40
		inc [i]
		mov ecx, [i]
	.endw
	invoke printf, $CTA0("\n")
	
	ret
PrintSectionTable endp

PrintExportTable proc stdcall uses ebx pe:DWORD

	local exp:DWORD
	local functionsArray:DWORD
	local namesArray:DWORD
	local nameOrdinalsArray:DWORD
	local i:DWORD
	local NoN:DWORD
	
	mov ebx, [pe]
	mov eax, [ebx].PeHeaders.expdir ;0x028dc964
	.if eax == 0
		ret
	.endif
	
	mov [exp], eax
	invoke puts, $CTA0("**********  Export Table:\n")
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 12]
	invoke RvaToOffset, edx, ebx
	mov edx, [ebx].PeHeaders.mem
	add edx, eax
	invoke printf, $CTA0("name: %s\n"), edx
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 4]
	invoke printf, $CTA0("time: %p\n"), edx
	
	mov edx, [exp]
	mov edx, dword ptr [edx]
	invoke printf, $CTA0("char: %p\n"), edx
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 16]
	invoke printf, $CTA0("base: %d\n"), edx
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 20]
	invoke printf, $CTA0("num fun: %d\n"), edx
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 24]
	invoke printf, $CTA0("num names: %d\n"), edx
	
	
	mov ebx, [pe]
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 28]
	invoke RvaToOffset, edx, ebx
	mov edx, [ebx].PeHeaders.mem
	add eax, edx
	mov [functionsArray], eax
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 32]
	invoke RvaToOffset, edx, ebx
	mov edx, [ebx].PeHeaders.mem
	add eax, edx
	mov [namesArray], eax
	
	mov edx, [exp]
	mov edx, dword ptr [edx + 36]
	invoke RvaToOffset, edx, ebx
	mov edx, [ebx].PeHeaders.mem
	add eax, edx
	mov [nameOrdinalsArray], eax
	
	mov [i], 0
	mov ecx, [i]
	mov eax, [exp]
	mov eax, dword ptr [eax + 24]
	mov [NoN], eax
	
	.while ecx < [NoN]
		
		mov eax, [nameOrdinalsArray]
		shl ecx, 1
		add ecx, eax
		movzx eax, word ptr [ecx]
		mov ecx, [exp]
		mov ecx, dword ptr [ecx + 16]
		add ecx, eax
		invoke printf, $CTA0("%d "), ecx
		
		mov eax, [namesArray]
		mov ecx, [i]
		shl ecx, 2
		add ecx, eax
		mov ecx, dword ptr [ecx]
		invoke RvaToOffset, ecx, ebx
		mov ecx, [ebx].PeHeaders.mem
		add ecx, eax
		invoke printf, $CTA0("%s\t"), ecx
		
		mov ecx, [i]
		mov eax, [nameOrdinalsArray]
		shl ecx, 1
		add eax, ecx
		movzx eax, word ptr [eax]
		mov edx, [functionsArray]
		shl eax, 2
		add edx, eax
		mov edx, dword ptr [edx]
		invoke printf, $CTA0("%p\n"), edx
		
		inc [i]
		mov ecx, [i]
	.endw
	
	invoke printf, $CTA0("\n")

	ret
	
PrintExportTable endp

PrintHexLine proc stdcall uses ebx line:DWORD, lineSize:DWORD

	local i:DWORD
	
	mov [i], 0
	mov ecx, [i]
	.while ecx < [lineSize]
		mov edx, [line]
		add edx, ecx
		movzx edx, byte ptr [edx]
		invoke printf, $CTA0("%02X "), edx
		
		inc [i]
		mov ecx, [i]
	.endw
	
	invoke printf, $CTA0("  ")
	
	mov [i], 0
	mov ecx, [i]
	
	.while ecx < [lineSize]
		mov edx, [line]
		add edx, ecx
		mov dl, byte ptr [edx]
		invoke isprint, dl
		.if eax
			mov edx, [line]
			add edx, [i]
			mov dl, byte ptr [edx]
			invoke printf, $CTA0("%c"), dl
		.else
			invoke printf, $CTA0(" ")
		.endif
		
		inc [i]
		mov ecx, [i]
	.endw
	
	ret

PrintHexLine endp

PrintDump proc stdcall uses ebx mem:DWORD, bytesFromMemoryCount:DWORD, bytesTotalCount:DWORD, printAddress:DWORD, bytesPerLine:DWORD, prefixName:DWORD

	local bytesIndex:DWORD
	local line:DWORD
	local lineIndex:DWORD
	
	mov [lineIndex], 0
	
	invoke malloc, dword ptr [bytesPerLine]
	mov [line], eax
	
	mov [bytesIndex], 0
	mov ecx, dword ptr [bytesIndex]
	.while ecx < [bytesTotalCount]
	
		mov edx, 0
		mov eax, ecx
		mov ebx, [bytesPerLine]
		div ebx
		
		.if edx == 0
			mov edx, dword ptr [printAddress]
			add edx, dword ptr [bytesIndex]
			invoke printf, $CTA0("%s %p: "), [prefixName], edx
		.endif
		
		mov ecx, dword ptr [bytesIndex]
		.if ecx < [bytesFromMemoryCount]
			mov edx, dword ptr [line]
			add edx, dword ptr [lineIndex]
			
			mov ebx, dword ptr [mem]
			add ebx, dword ptr [bytesIndex]
			
			mov bl, byte ptr [ebx]
			mov byte ptr [edx], bl
			
			inc [lineIndex]
		.else
			mov edx, dword ptr [line]
			add edx, dword ptr [lineIndex]
			mov byte ptr [edx], 0
			
			inc [lineIndex]
		.endif
		
		mov edx, 0
		mov eax, [bytesIndex]
		inc eax
		div dword ptr [bytesPerLine]
		.if edx == 0
			invoke PrintHexLine, dword ptr [line], dword ptr [bytesPerLine]
			invoke printf, $CTA0("\n")
			mov [lineIndex], 0
		.endif
		
		inc [bytesIndex]
		mov ecx, [bytesIndex]
	.endw
	
	invoke free, dword ptr [line]
	
	ret
	
PrintDump endp

PrintSectionInFileDump proc stdcall uses ebx pe:DWORD, sectionNumber:DWORD, bytesPerLine:DWORD

	local sec:DWORD
	
	mov ebx, [pe]
	mov edx, [ebx].PeHeaders.sections
	mov ecx, [sectionNumber]
	push edx
	imul ecx, 40
	pop edx
	add edx, ecx
	mov [sec], edx
	
	mov edx, [sec]
	mov eax, [ebx].PeHeaders.mem
	mov edx, dword ptr [edx + 20]
	add edx, eax
	
	push edx
	mov ecx, [sec]
	mov eax, [ebx].PeHeaders.nthead
	mov eax, dword ptr [eax + 24 + 36]
	invoke AlignToTop, dword ptr [ecx + 16], eax
	
	pop edx
	mov ecx, [sec]
	mov ebx, eax
	invoke PrintDump,
					edx,
					dword ptr [ecx + 16],
					ebx,
					dword ptr [ecx + 20],
					dword ptr [bytesPerLine],
					addr [ecx]
					
	invoke printf, $CTA0("\n")

	ret
	
PrintSectionInFileDump endp
	
PrintSectionsInFileDump proc stdcall uses ebx pe:DWORD, bytesPerLine:DWORD

	local i:DWORD
	local csec:DWORD
	
	mov ebx, [pe]
	mov eax, [ebx].PeHeaders.countSec
	mov dword ptr [csec], eax
	
	mov [i], 0
	mov ecx, [i]
	.while ecx < [csec]
	
		invoke PrintSectionInFileDump, dword ptr [pe], dword ptr [i], dword ptr [bytesPerLine]
		
		inc [i]
		mov ecx, [i]
	.endw

	ret

PrintSectionsInFileDump endp

PrintSectionInMemoryDump proc stdcall uses ebx pe:DWORD, sectionNumber:DWORD, bytesPerLine:DWORD

	local sec:DWORD
	local minSize:DWORD
	local tmpSum:DWORD
	
	mov ebx, [pe]
	mov edx, [ebx].PeHeaders.sections
	mov ecx, dword ptr [sectionNumber]
	push edx
	imul ecx, 40
	pop edx
	add edx, ecx
	mov [sec], edx
	
	mov edx, [sec]
	mov eax, [ebx].PeHeaders.mem
	mov edx, dword ptr [edx + 20]
	add edx, eax
	
	push edx
	mov ecx, [sec]
	mov eax, [ebx].PeHeaders.nthead
	mov eax, dword ptr [eax + 24 + 32]
	invoke AlignToTop, dword ptr [ecx + 8], eax
	
	pop edx
	mov ecx, [sec]
	mov ecx, dword ptr [ecx + 16]
	mov [minSize], ecx
	mov ecx, [sec]
	mov ecx, dword ptr [ecx + 8]
	
	.if ecx < [minSize]
		mov [minSize], ecx
	.endif
	
	mov ecx, [sec]
	mov ecx, dword ptr [ecx + 12]
	mov [tmpSum], ecx
	
	mov ecx, [ebx].PeHeaders.nthead
	mov ecx, dword ptr [ecx + 24 + 28]
	add ecx, [tmpSum]
	mov [tmpSum], ecx
	
	mov ecx, dword ptr [sec]
	mov ebx, eax
	invoke PrintDump,
					edx,
					dword ptr [minSize],
					ebx,
					dword ptr [tmpSum],
					dword ptr [bytesPerLine],
					addr [ecx]
					
	invoke printf, $CTA0("\n")

	ret
	
PrintSectionInMemoryDump endp

PrintSectionsInMemoryDump proc stdcall uses ebx pe:DWORD, bytesPerLine:DWORD
	local i:DWORD
	local csec:DWORD
	
	mov ebx, [pe]
	mov eax, [ebx].PeHeaders.countSec
	mov dword ptr [csec], eax
	
	mov [i], 0
	mov ecx, [i]
	.while ecx < [csec]
	
		invoke PrintSectionInMemoryDump, dword ptr [pe], dword ptr [i], dword ptr [bytesPerLine]
		
		inc [i]
		mov ecx, [i]
	.endw

	ret

PrintSectionsInMemoryDump endp


PrintHeadersInFileDump proc stdcall uses ebx pe:DWORD, bytesPerLine:DWORD

	mov ebx, [pe]
	mov edx, [ebx].PeHeaders.nthead
	
	mov ecx, dword ptr [edx + 24 + 60]
	
	invoke PrintDump, [ebx].PeHeaders.mem, ecx, ecx, 0, [bytesPerLine], $CTA0("hdr")
	
	ret

PrintHeadersInFileDump endp


PrintHeadersInMemoryDump proc stdcall uses ebx pe:DWORD, bytesPerLine:DWORD

	mov ebx, [pe]
	mov edx, [ebx].PeHeaders.nthead
	invoke AlignToTop, dword ptr [edx + 24 + 60], dword ptr [edx + 24 + 32]
	mov ecx, eax
	
	mov edx, [ebx].PeHeaders.nthead
	
	invoke PrintDump, [ebx].PeHeaders.mem, dword ptr [edx + 24 + 60], ecx, dword ptr [edx + 24 + 28], [bytesPerLine], $CTA0("hdr")	
	
	ret

PrintHeadersInMemoryDump endp


PrintFileDump proc stdcall pe:DWORD, bytesPerLine:DWORD

	invoke PrintHeadersInFileDump, [pe], [bytesPerLine]
	invoke PrintSectionsInFileDump, [pe], [bytesPerLine]
	
	ret

PrintFileDump endp


PrintImageDump proc stdcall pe:DWORD, bytesPerLine:DWORD

	invoke PrintHeadersInMemoryDump, [pe], [bytesPerLine]
	invoke PrintSectionsInMemoryDump, [pe], [bytesPerLine]
	
	ret

PrintImageDump endp


PrintSectionInFileDumpByName proc stdcall pe:DWORD, bytesPerLine:DWORD, secname:DWORD

	local indexSec:DWORD
	
	invoke GetSectionIndexByName, [pe], [secname]
	mov [indexSec], eax
	
	.if eax == 0FFFFFFFFh
		ret
	.endif
	
	invoke PrintSectionInFileDump, [pe], [indexSec], [bytesPerLine]
	
	ret
	
PrintSectionInFileDumpByName endp


PrintSectionInMemoryDumpByName proc stdcall pe:DWORD, bytesPerLine:DWORD, secname:DWORD

	local indexSec:DWORD
	
	invoke GetSectionIndexByName, [pe], [secname]
	mov [indexSec], eax
	
	.if eax == 0FFFFFFFFh
		ret
	.endif
	
	invoke PrintSectionInMemoryDump, [pe], [indexSec], [bytesPerLine]
	
	ret
	
PrintSectionInMemoryDumpByName endp


PrintBaseReloc proc stdcall uses ebx pe:DWORD

	local offset1:DWORD
	local reloc:DWORD
	local relocType[11]:DWORD
	local baseRelocOffset:DWORD
	local SizeOfReloc:DWORD
	local i:DWORD
	local tmp:DWORD
	
	lea eax, [relocType]
	
	mov [eax], $CTA0("IMAGE_REL_BASED_ABSOLUTE")
	mov [eax + 4], $CTA0("IMAGE_REL_BASED_HIGH")
	mov [eax + 8], $CTA0("IMAGE_REL_BASED_LOW")
	mov [eax + 12], $CTA0("IMAGE_REL_BASED_HIGHLOW")
	mov [eax + 16], $CTA0("IMAGE_REL_BASED_HIGHADJ")
	mov [eax + 20], $CTA0("IMAGE_REL_BASED_MIPS_JMPADDR")
	mov [eax + 24], $CTA0("")
	mov [eax + 28], $CTA0("")
	mov [eax + 32], $CTA0("")
	mov [eax + 36], $CTA0("IMAGE_REL_BASED_IA64_IMM64")
	mov [eax + 40], $CTA0("IMAGE_REL_BASED_DIR64")
	
	mov ebx, [pe]
	
	mov eax, [ebx].PeHeaders.nthead
	movzx eax, word ptr [eax + 22]
	and eax, IMAGE_FILE_RELOCS_STRIPPED
	.if eax
		ret
	.endif
	
	mov eax, [ebx].PeHeaders.nthead
	mov ecx, dword ptr [eax + 24 + 96 + 40] ; 24 - OptHeader, 96 - DDir, 40 - BReloc
	mov eax, dword ptr [eax + 24 + 96 + 40 + 4]
	push eax
	push ecx
	.if !ecx || !eax
		ret
	.endif
	pop ecx
	
	invoke RvaToOffset, ecx, ebx
	mov ecx, [ebx].PeHeaders.mem
	add eax, ecx
	mov [reloc], eax
	pop eax
	mov [SizeOfReloc], eax
	
	mov [offset1], 0
	mov ecx, [offset1]
	
	.while ecx < [SizeOfReloc]
		mov ebx, [reloc]
		
		mov eax, ebx
		add eax, sizeof(IMAGE_BASE_RELOCATION)
		mov [baseRelocOffset], eax
		
		mov [i], 0
		mov ecx, [i]
		
		mov eax, dword ptr [ebx + 4]
		sub eax, sizeof(IMAGE_BASE_RELOCATION)
		shr eax, 1
		mov [tmp], eax
		
		.while ecx < [tmp]
			
			mov eax, [baseRelocOffset]
			shl ecx, 1
			add eax, ecx
			movzx eax, word ptr [eax]
			push eax
			and eax, 0FFFh
			mov ecx, dword ptr [ebx]
			add ecx, eax
			
			pop eax
			lea edx, [relocType]
			shr eax, 12 ;10
			shl eax, 2
			add edx, eax
			mov edx, dword ptr [edx]
			
			invoke printf, $CTA0("%x\t%s\n"), ecx, edx
			
			inc [i]
			mov ecx, [i]
		.endw
	
		mov ecx, dword ptr [ebx + 4]
		add ecx, ebx
		mov [reloc], ecx
	
		mov eax, dword ptr [ebx + 4]
		add [offset1], eax
		mov ecx, [offset1]
	.endw

	ret
	
PrintBaseReloc endp

end
	


	
	
	
		 
