#include "mydbg.h"

void DbgPrint(char* FormatStr, ...)
{
	va_list vaList;
	va_start(vaList, FormatStr);
#ifdef WIN32
	char dbgout[1000];
	sprintf_s(dbgout, 1000, FormatStr, vaList);
	OutputDebugStringA(dbgout);
#endif
#ifdef LINUX
	vfprintf(stderr, FormatStr, vaList);
#endif
	va_end(vaList);
}