#include <stdio.h>
#include <stdarg.h>

#ifdef WIN32
#include <Windows.h>
#include <debugapi.h>
#endif

void DbgPrint(char* FormatStr, ...);