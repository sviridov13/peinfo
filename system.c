/*

������ ��������������� ��������� �������.

������ ���� �������������   15.11.2012

*/


#include <windows.h>
#include <stdio.h>

#include "system.h"


//----------------------------------------

//----------------------------------------


//
// ���������� ������ ��������� �� �������.
//
void PrintErrorMessage (unsigned int err) {

LPTSTR msg;

    DWORD res = FormatMessage (
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        NULL,
        err,    // ��� ������
        0,      // ������������� ����� ��-���������
        (LPTSTR) &msg,
        0,
        NULL);

    if (res) {
        printf("%s",msg);
        LocalFree(msg);         // ������������ ������ � ������� ���������
        }

    return;
}


//
// ���������� ������ ��������� � ��������� ������.
//
void PrintLastErrorMessage() {

    PrintErrorMessage (GetLastError());
}


//----------------------------------------
