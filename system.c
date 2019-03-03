/*

Модуль вспомогательных системных функций.

Маткин Илья Александрович   15.11.2012

*/


#include <windows.h>
#include <stdio.h>

#include "system.h"


//----------------------------------------

//----------------------------------------


//
// Отладочная печать сообщений об ошибках.
//
void PrintErrorMessage (unsigned int err) {

LPTSTR msg;

    DWORD res = FormatMessage (
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
        NULL,
        err,    // код ошибки
        0,      // идентификатор языка по-умолчанию
        (LPTSTR) &msg,
        0,
        NULL);

    if (res) {
        printf("%s",msg);
        LocalFree(msg);         // освобождение буфера с текстом сообщения
        }

    return;
}


//
// Отладочная печать сообщения о последней ошибке.
//
void PrintLastErrorMessage() {

    PrintErrorMessage (GetLastError());
}


//----------------------------------------
