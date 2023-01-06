#include "mydbg.h"

void DbgPrint(char* FormatStr, ...)
{
	char dbgout[1000];
	va_list vaList;

	va_start(vaList, FormatStr);
	sprintf(dbgout, FormatStr, vaList);
	OutputDebugStringA(dbgout);
	va_end(vaList);
}