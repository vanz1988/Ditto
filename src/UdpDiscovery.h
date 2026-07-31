#pragma once
#include <winsock2.h>
#include <stdio.h>
#include "Options.h"
#include "..\Shared\TextConvert.h"
#include "Misc.h"

#define UDP_DISCOVERY_PORT 23444
#define UDP_DISCOVERY_INTERVAL_MS 30000

class CUdpDiscoveryThread
{
public:
	CUdpDiscoveryThread();
	~CUdpDiscoveryThread();

	void Start();
	void Stop();

private:
	static unsigned int __stdcall ThreadFunc(void* thisptr);
	void Run();

	bool m_running;
	HANDLE m_threadHandle;
	unsigned int m_threadId;
	CCriticalSection m_lock;

	SOCKET m_sock;
	CString m_localIP;
	CString m_localName;
	CString m_computerName;

	CString GetLocalIPAddress();
	bool IsIPInFriends(const CString& csIP);
	void AddIPToFriends(const CString& csIP);
	bool ParseHeartbeat(const char* buf, int len, CString& ip, CString& name);
	void SendHeartbeat();
};
