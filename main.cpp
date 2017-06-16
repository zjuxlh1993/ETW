
//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID

#pragma warning(disable:4996)

#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <sstream>
#include <set>
#include <stdlib.h>
#include <memory>
#include <atlconv.h>
#include <unordered_map>

using namespace std;

#include "getAddress.h"


#pragma comment(lib, "tdh.lib")

#define LOGFILE_PATH L"G:\\source\\DIA_findSymbolByVA\\record.etl"

ULONG g_TimerResolution = 0;


BOOL g_bUserMode = FALSE;


TRACEHANDLE g_hTrace = 0;


void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
BOOL pidInWhitelist(DWORD pid);
using namespace std;

wofstream outFile;
DWORD  MessageCount;
DWORD curPID[4] = { 0L };
getAddress g;
string path = "";
set<DWORD> whiteListPID;
int CPID;

DWORD fileObject;
unordered_map<DWORD, string> fileNameMap;

void wmain(int argc, char* argv[])

{
	short sum = 0;
	whiteListPID.clear();
	whiteListPID.insert(GetCurrentProcessId());
	cout << "Initialized." << endl;
	MessageCount = 0L;
begin:
	TDHSTATUS status = ERROR_SUCCESS;//设置etw
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = KERNEL_LOGGER_NAME;
	trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(ProcessEvent);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	g_hTrace = OpenTrace(&trace);
	if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

	if (pHeader->PointerSize != sizeof(PVOID))
	{
		pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
			2 * (pHeader->PointerSize - sizeof(PVOID)));
	}

	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}




cleanup:

	if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
	{
		status = CloseTrace(g_hTrace);
	}
	outFile.clear();
	WSACleanup();
	goto begin;

}


VOID WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
	DWORD status = ERROR_SUCCESS;
	PBYTE pUserData = NULL;
	UCHAR OPcode;
	DWORD PointerSize = 0;
	ULONGLONG TimeStamp = 0;
	ULONGLONG Nanoseconds = 0;
	string strName = "";
	string parm = "";
	CPID = 0;
	OPcode = pEvent->EventHeader.EventDescriptor.Opcode;//OPcode是event type value
	if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
		(!OPcode))
	{
		wprintf(L"A Event is being skipped\n");
	}
	else
	if (
		OPcode == 10
		|| OPcode == 11
		|| OPcode == 32
		|| OPcode == 36
		|| OPcode == 51
		|| OPcode == 16
		|| OPcode == 64
		|| OPcode == 74
		|| OPcode == 72
		|| OPcode == 33
		|| OPcode == 34
		|| OPcode == 15
		|| OPcode == 12
		|| OPcode == 13
		)
	{

		pUserData = (PBYTE)pEvent->UserData;
		if (OPcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2586315456){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}else
		if (OPcode == 12 && pEvent->EventHeader.ProviderId.Data1 == 2586315456){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}else
		if (OPcode == 13 && pEvent->EventHeader.ProviderId.Data1 == 2586315456){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}else
		if (OPcode == 15 && pEvent->EventHeader.ProviderId.Data1 == 2586315456){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}
		if (OPcode == 33 && pEvent->EventHeader.ProviderId.Data1 == 1171836109){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}else
		if (OPcode == 34 && pEvent->EventHeader.ProviderId.Data1 == 1171836109){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}
		if (OPcode == 51){
			DWORD address = *(DWORD *)pUserData;
			address &= 0xFFFFFFF;
			USES_CONVERSION;
			if (g.addressToName.find(address) != g.addressToName.end())
				strName = string(W2A(g.addressToName[address]));
			CPID = curPID[pEvent->BufferContext.ProcessorNumber];
		}
		else
		if (OPcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2924704302){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}
		else
		if (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 == 1030727889){
			//CS
			DWORD threadID = *(DWORD *)pUserData;
			int processorID = pEvent->BufferContext.ProcessorNumber;
			curPID[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
		}
		else
		if (OPcode == 16 && pEvent->EventHeader.ProviderId.Data1 == 2924704302){
			pUserData += 24;
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			CPID = pEvent->EventHeader.ProcessId;
		}
		else
		if (OPcode == 72){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			pUserData += 8;
			fileObject = *(DWORD *)pUserData;
			parm=fileNameMap[fileObject];
		}
		else
		if (OPcode == 32 && pUserData&& pEvent->EventHeader.ProviderId.Data1 == 2429279289){
			fileObject = *(DWORD *)pUserData;
			pUserData += 8;
			//strName = "NtCreateFile";
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			fileNameMap[fileObject] = parm;
			goto cleanup;
		}
		else
		if (OPcode == 64){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			pUserData += 8;
			fileObject = *(DWORD*)pUserData;
			pUserData += 20;
			//strName = "NtCreateFile";
			USES_CONVERSION;
			parm = string(W2A((wchar_t *)pUserData));
			fileNameMap[fileObject] = parm;
		}
		else
		if (OPcode == 74){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			pUserData += 8;
			fileObject = *(DWORD *)pUserData;
			//strName = "NtCreateFile";
			parm = fileNameMap[fileObject];
		}
		else
		if (OPcode == 10){
			pUserData += 0;
			if (pEvent->EventHeader.ProviderId.Data1 == 749821213){
				pUserData += 16;
				CPID = *(DWORD*)pUserData;
				pUserData += 40;
				//strName = "NtOpenSection";
				USES_CONVERSION;
				parm = string(W2A((wchar_t*)pUserData));
			}
			else
			if (pEvent->EventHeader.ProviderId.Data1 == 2924704302){
				pUserData += 24;
				//strName = "NtCreateKey";
				USES_CONVERSION;
				parm = string(W2A((wchar_t*)pUserData));
				CPID = pEvent->EventHeader.ProcessId;
			}
		}
	cleanup:
		if (CPID)
		{
			if (!pidInWhitelist(CPID))
			{
				MessageCount++;
				if (MessageCount % 10000 == 0)
				{
					wcout << L"published " << MessageCount << L" messages!" << endl;
				}
			}

		}

		if (ERROR_SUCCESS != status || NULL == pUserData)
		{
			CloseTrace(g_hTrace);
		}
	}
}

BOOL pidInWhitelist(DWORD pid){
	string a;

	set<DWORD>::iterator i = whiteListPID.find(pid);
	if (i != whiteListPID.end())
		return true;
	else
		return false;
}