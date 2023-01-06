#include "mydbg.h"

void DbgPrint(char* FormatStr, ...)
{
	char dbgout[1000];
	va_list vaList;

	va_start(vaList, FormatStr);
	sprintf_s(dbgout, 1000, FormatStr, vaList);
	OutputDebugStringA(dbgout);
	va_end(vaList);
}