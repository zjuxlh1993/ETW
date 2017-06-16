
//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID


//#include <Winsock2.h>
//#include <WS2tcpip.h>
//#pragma comment(lib, "ws2_32.lib")
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

#include <activemq/util/Config.h>

#include <decaf/lang/System.h>
#include <decaf/lang/Runnable.h>
#include <decaf/lang/Integer.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/library/ActiveMQCPP.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/Destination.h>
#include <cms/MessageProducer.h>
#include <cms/TextMessage.h>
#define MaxSendNum 10000
using namespace cms;
using namespace activemq;
using namespace activemq::core;
using namespace decaf;
using namespace decaf::lang;

using namespace std;

#include "getAddress.h"


#pragma comment(lib, "tdh.lib")

#define LOGFILE_PATH L"G:\\source\\DIA_findSymbolByVA\\record.etl"

// Used to calculate CPU usage

ULONG g_TimerResolution = 0;

// Used to determine if the session is a private session or kernel session.
// You need to know this when accessing some members of the EVENT_TRACE.Header
// member (for example, KernelTime or UserTime).

BOOL g_bUserMode = FALSE;

// Handle to the trace file that you opened.

TRACEHANDLE g_hTrace = 0;

// Prototypes

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
PBYTE PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, DWORD PointerSize, USHORT i, PBYTE pUserData, PBYTE pEndOfUserData);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT PropertyLength);
DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);
DWORD GetPIDbyThreadID(DWORD threadID);
DWORD PCharToDWORD(LPWSTR pFormattedData);
LPWSTR addressTosyscall(DWORD address);
DWORD string16ToDword(string s);
string getEnv(const string& key, const string& defaultValue);
string getArg(char* argv[], int argc, int index, const string& defaultValue);
string GetPathbyPID(DWORD pid);
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
BOOL pidInWhitelist(DWORD pid);
string changeSeparator(string ss);
SOCKET sockClient;
using namespace std;

//global values
wofstream outFile;
DWORD  MessageCount;
DWORD curPID[4] = { 0L };
getAddress g;
string path = "";
set<DWORD> whiteListPID;
int CPID;
int data[MaxSendNum+1];

// hash map for file name
DWORD fileObject;
unordered_map<DWORD ,string> fileNameMap;
unordered_map<DWORD, short> ParmToNum;
unordered_map<string, short> FToNum;
short strnum; 
int parmnum;
//global values for activeMQ
std::auto_ptr<MessageProducer> producer;
std::auto_ptr<TextMessage> message;
std::auto_ptr<Session> session;

void wmain(int argc, char* argv[])

{
	data[MaxSendNum] = 0;
	fstream fin;
	fin.open("Text.txt", fstream::in);
	string Parameter="";
	int ParaNo;
	while (fin >> ParaNo >> Parameter){
		FToNum[Parameter] = ParaNo;
	}
    fin.close();//read the gram of parameter
	short sum = 0;
	for (map<DWORD, LPCWSTR>::iterator iter = g.addressToName.begin(); iter != g.addressToName.end(); iter++){
		USES_CONVERSION;
		ParmToNum[iter->first]=sum;
		sum++;
	}

	//outFile.open("TraceOfETW.txt");
	whiteListPID.clear();
	whiteListPID.insert(GetCurrentProcessId());
	//WORD wVersionRequested;
	//WSADATA wsaData;
	//int err;

	//wVersionRequested = MAKEWORD(1, 1);

	//err = WSAStartup(wVersionRequested, &wsaData);
	//if (err != 0) {
	//	return;
	//}

	//if (LOBYTE(wsaData.wVersion) != 1 ||
	//	HIBYTE(wsaData.wVersion) != 1) {
	//	WSACleanup();
	//	return;
	//}
	//sockClient = socket(AF_INET, SOCK_STREAM, 0);

	//SOCKADDR_IN addrSrv;
	//inet_pton(AF_INET, "192.168.152.129", &(addrSrv.sin_addr.S_un.S_addr));
	//addrSrv.sin_family = AF_INET;
	//addrSrv.sin_port = htons(6000);
	//int ret = connect(sockClient, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	activemq::library::ActiveMQCPP::initializeLibrary();

	cout << "=====================================================\n";
	cout << "Starting the Publisher :" << std::endl;
	cout << "-----------------------------------------------------\n";

	string user = getEnv("ACTIVEMQ_USER", "admin");
	string password = getEnv("ACTIVEMQ_PASSWORD", "admin");
	string host = getEnv("ACTIVEMQ_HOST", "192.168.152.129");
	int port = Integer::parseInt(getEnv("ACTIVEMQ_PORT", "61616"));
	string destination = getArg(argv, argc, 1, "event");

	ActiveMQConnectionFactory factory;
	factory.setBrokerURI(std::string("tcp://") + host + ":" + Integer::toString(port));

	auto_ptr<Connection> connection(factory.createConnection(user, password));

	connection->start();
	auto_ptr<Session> ss(connection->createSession());
	session = ss;
	auto_ptr<Destination> dest(session->createTopic(destination));
	auto_ptr<MessageProducer> pp(session->createProducer(dest.get()));
	producer = pp;

	producer->setDeliveryMode(DeliveryMode::NON_PERSISTENT);
	cout << "Initialized." << endl;
	MessageCount = 0L;
begin:
	TDHSTATUS status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;

	// Identify the log file from which you want to consume events
	// and the callbacks used to process the events and buffers.

	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = KERNEL_LOGGER_NAME;
	//	trace.LoggerName = L"Windows Kernel Trace";
	trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(ProcessEvent);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	g_hTrace = OpenTrace(&trace);
	if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}		

	g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

	// Use pHeader to access all fields prior to LoggerName.
	// Adjust pHeader based on the pointer size to access
	// all fields after LogFileName. This is required only if
	// you are consuming events on an architecture that is 
	// different from architecture used to write the events.

	if (pHeader->PointerSize != sizeof(PVOID))
	{
		pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
			2 * (pHeader->PointerSize - sizeof(PVOID)));
	}

	//    wprintf(L"Number of buffers lost: %lu\n\n", pHeader->BuffersLost);


	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}





cleanup:

//	wprintf(L"The process is ended with %lu\n", status);
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
	string strName="";
	string parm="";
	CPID = 0;
	strnum = 127;
	parmnum = 511;
	OPcode = pEvent->EventHeader.EventDescriptor.Opcode;
	if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
		(!OPcode))
	{
		wprintf(L"A Event is being skipped\n");
		; // Skip this event.
	}
	// Skips the event if it is not SysClEnter(51) or CSwitch(36).
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

		)
	{
		pUserData = (PBYTE)pEvent->UserData;
		if (OPcode == 51){
			DWORD address = *(DWORD *)pUserData;
			address &= 0xFFFFFFF;
			USES_CONVERSION;
			if (g.addressToName.find(address) != g.addressToName.end())
				//strName = W2A(g.addressToName[address]);
			    strnum=ParmToNum[address];
			CPID = curPID[pEvent->BufferContext.ProcessorNumber];
			goto cleanup;
		}
		else
		if (OPcode == 11 && pEvent->EventHeader.ProviderId.Data1 == 2924704302){
			//strName = "NtOpenKey";
			strnum=30;
			pUserData += 24;
			USES_CONVERSION;
			PBYTE last_backslash = pUserData;
			while (unsigned short charpos = *(unsigned short*)pUserData){
				pUserData += 2;
				if (charpos == 92) last_backslash = pUserData;
			}
			unordered_map<string, short>::iterator iter = FToNum.find((string)W2A((wchar_t*)last_backslash));
			if (iter != FToNum.end()) parmnum = iter->second;
			CPID = pEvent->EventHeader.ProcessId;
			goto cleanup;
		}
		else
		if (OPcode == 36 && pEvent->EventHeader.ProviderId.Data1 ==1030727889){
			DWORD threadID = *(DWORD *)pUserData;
			//outFile << threadID <<' '<<*(DWORD*)(pUserData+4)<< endl;
			int processorID = pEvent->BufferContext.ProcessorNumber;
			curPID[processorID] = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			goto cleanup;
		}
		else
		if (OPcode == 16 && pEvent->EventHeader.ProviderId.Data1 == 2924704302){
			pUserData += 24;
			//strName = "NtQueryValueKey";
			strnum=23;
			USES_CONVERSION;
			PBYTE last_backslash = pUserData;
			while (unsigned short charpos = *(unsigned short*)pUserData){
				pUserData += 2;
				if (charpos == 92) last_backslash = pUserData;
			}
			unordered_map<string, short>::iterator iter = FToNum.find((string)W2A((wchar_t*)last_backslash));
			if (iter != FToNum.end()) parmnum = iter->second;
			CPID = pEvent->EventHeader.ProcessId;
			goto cleanup;
		}
		else
		if (OPcode == 72){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			//strName = "NtQueryDirectoryFile";
			strnum=24;
			pUserData += 8;
			fileObject = *(DWORD *)pUserData;
			unordered_map<string, short>::iterator iter = FToNum.find(fileNameMap[fileObject]);
			parmnum = iter->second;
			goto cleanup;
		}
		else
		if (OPcode == 32 && pUserData&& pEvent->EventHeader.ProviderId.Data1 == 2429279289){
			fileObject = *(DWORD *)pUserData;
			pUserData += 8;
			//strName = "NtCreateFile";
			strnum=0;
			USES_CONVERSION;
			PBYTE last_backslash = pUserData;
			while (unsigned short charpos = *(unsigned short*)pUserData){
				pUserData += 2;
				if (charpos == 92) last_backslash = pUserData;
			}
			parm = W2A((wchar_t*)last_backslash);
			unordered_map<string, short>::iterator iter = FToNum.find(parm);
			if (iter != FToNum.end()) parmnum = iter->second;
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
		    strnum=0;
			USES_CONVERSION;
			PBYTE last_backslash = pUserData;
			while (unsigned short charpos = *(unsigned short*)pUserData){
				pUserData += 2;
				if (charpos == 92) last_backslash = pUserData;
			}
			parm = W2A((wchar_t*)last_backslash);
			unordered_map<string, short>::iterator iter = FToNum.find(parm);
			if (iter != FToNum.end()) parmnum = iter->second;
			fileNameMap[fileObject] = parm;
			goto cleanup;
		}
		else
		if (OPcode == 74){
			pUserData += 8;
			DWORD threadID = *(DWORD *)pUserData;
			CPID = GetProcessIdOfThread(OpenThread(THREAD_QUERY_INFORMATION, false, threadID));
			pUserData +=8 ;
			fileObject = *(DWORD *)pUserData;
			//strName = "NtCreateFile";
			strnum=0;
			PBYTE last_backslash = pUserData;
			while (DWORD charpos = *(DWORD*)pUserData){
				pUserData += 2;
				if (charpos = 92) last_backslash = pUserData;
			}
			unordered_map<string, short>::iterator iter = FToNum.find(fileNameMap[fileObject]);
			if (iter != FToNum.end()) parmnum = iter->second;
			goto cleanup;}
	    else
		if (OPcode == 10){
			pUserData += 0;
			if (pEvent->EventHeader.ProviderId.Data1 == 749821213){
				pUserData += 16;
				CPID = *(DWORD*)pUserData;
				pUserData += 40;
				//strName = "NtOpenSection";
				strnum=37;
				USES_CONVERSION;
				PBYTE last_backslash = pUserData;
				while (unsigned short charpos = *(unsigned short*)pUserData){
					pUserData += 2;
					if (charpos == 92) last_backslash = pUserData;
				}
				unordered_map<string, short>::iterator iter = FToNum.find((string)W2A((wchar_t*)last_backslash));
				if (iter != FToNum.end()) parmnum = iter->second;
			}else
			if (pEvent->EventHeader.ProviderId.Data1 == 2924704302){
				pUserData += 24;
				//strName = "NtCreateKey";
				strnum = 49;
				USES_CONVERSION;
				PBYTE last_backslash = pUserData;
				while (unsigned short charpos = *(unsigned short*)pUserData){
					pUserData += 2;
					if (charpos == 92) last_backslash = pUserData;
				}
				unordered_map<string, short>::iterator iter = FToNum.find((string)W2A((wchar_t*)last_backslash));
				if (iter != FToNum.end()) parmnum = iter->second;
				CPID = pEvent->EventHeader.ProcessId;
			}
		}
	cleanup:
		if (CPID&&strnum!=127/*strName!=""*/)
		{
			if (!pidInWhitelist(CPID))
			{
				//stringstream ss;
				//ss << " { ";
				//ss << "\"syscall\": \"";
				//ss << strName;
				//ss << "\",";
				//ss << "\"pid\" : ";
				//ss << CPID;
				//ss << ", \"path\" : \"";
				//ss << path;
				//ss << "\",";
				//ss << "\"parameter\" : \"";
				//ss << parm;
				//			ss << "\",";
				//			ss << "\"eventType\" : ";
				//			ss << (int)OPcode;
				//ss << "\" }";
				if (MessageCount % MaxSendNum == 0&&MessageCount!=0){
					char *pdata; 
					pdata= (char*)data;
					string str = string(pdata,MaxSendNum*4);
					message.reset(session->createTextMessage(str));
					producer->send(message.get());
				}
				//string messageBody = ss.str();
				data[MessageCount%MaxSendNum] = (((strnum << 1) + parmnum / 256) << 24) + (parmnum % 256 << 16) + (CPID / 256 << 8) + CPID % 256;
				MessageCount++;
				 //reset
			     //message.reset(session->createTextMessage(boost::asio::buffer(data)));
				//			cout << data << endl;
				//send to activeMQ
				//output to local file
				//outFile << messageBody.c_str() << endl;
				//outFile << data << endl;
				//outFile << hex << (((strnum << 1) + parmnum / 256) << 24) + (parmnum % 256 << 16) + (CPID / 256 << 8) + CPID % 256 << ' ';
				//cout << messageBody.c_str() << endl;
				//int ret;
				//if ((ret = send(sockClient, (char*)&data, 4, 0)) < 0)
				//	{
				//		printf("errno: %d\n", WSAGetLastError());
				//	}
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
string getEnv(const string& key, const string& defaultValue) {

	try{
				return System::getenv(key);
	}
	catch (...) {
	}

	return defaultValue;
}

//////////////////////////////////////////////////////////////////////////////
string getArg(char* argv[], int argc, int index, const string& defaultValue) {

	if (index < argc) {
		return argv[index];
	}

	return defaultValue;
}

