#include "stdafx.h"
#include "UdpDiscovery.h"
#include "Misc.h"
#include "Options.h"
#include "..\Shared\TextConvert.h"
#include <IPHlpApi.h>

#pragma comment(lib, "IPHlpApi.lib")

CUdpDiscoveryThread::CUdpDiscoveryThread()
{
	m_running = false;
	m_threadHandle = NULL;
	m_threadId = 0;
	m_sock = INVALID_SOCKET;
	m_localIP = _T("");
	m_computerName = _T("");
	{
		TCHAR szName[256];
		DWORD dwLen = 256;
		if(GetComputerName(szName, &dwLen))
			m_computerName = szName;
		else
			m_computerName = _T("Ditto");
	}
}

CUdpDiscoveryThread::~CUdpDiscoveryThread()
{
	Stop();
}

CString CUdpDiscoveryThread::GetLocalIPAddress()
{
	CString csIP = _T("");
	DWORD dwBufLen = 15000;
	ULONG dwRet;

	PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(dwBufLen);
	if(pAdapterInfo == NULL)
		return csIP;

	dwRet = GetAdaptersInfo(pAdapterInfo, &dwBufLen);
	if(dwRet != ERROR_SUCCESS)
	{
		free(pAdapterInfo);
		return csIP;
	}

	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	while(pAdapter != NULL)
	{
		PIP_ADDR_STRING pAddr = &(pAdapter->IpAddressList);
		while(pAddr != NULL)
		{
			CString csCurIP(pAddr->IpAddress.String);
			if(csCurIP.Find(_T("127.")) == -1)
			{
				csIP = csCurIP;
				break;
			}
			pAddr = pAddr->Next;
		}
		if(csIP.GetLength() > 0)
			break;
		pAdapter = pAdapter->Next;
	}

	free(pAdapterInfo);
	return csIP;
}

bool CUdpDiscoveryThread::IsIPInFriends(const CString& csIP)
{
	CString csTarget = csIP;
	csTarget.MakeUpper();
	for(int i = 0; i < MAX_SEND_CLIENTS; i++)
	{
		CString csCur = CGetSetOptions::m_SendClients[i].csIP;
		csCur.MakeUpper();
		if(csCur == csTarget)
			return true;
	}
	return false;
}

void CUdpDiscoveryThread::AddIPToFriends(const CString& csIP)
{
	CString csHostName = _T("");
	CStringA csIPA = CTextConvert::UnicodeToAnsi(csIP);
	struct hostent* pHost = gethostbyaddr(csIPA, sizeof(struct in_addr), AF_INET);
	if(pHost)
		csHostName = pHost->h_name;

	CString csDesc;
	csDesc.Format(_T("%s (%s)"), csIP, csHostName);

	int nPos = -1;
	for(int i = 0; i < MAX_SEND_CLIENTS; i++)
	{
		if(CGetSetOptions::m_SendClients[i].csIP.GetLength() == 0)
		{
			nPos = i;
			break;
		}
	}

	if(nPos >= 0)
	{
		CSendClients client;
		client.csIP = csIP;
		client.csDescription = csDesc;
		client.bSendAll = TRUE;
		client.bShownFirstError = FALSE;

		CGetSetOptions::SetSendClients(client, nPos);
		CGetSetOptions::GetClientSendCount();

		CString cs;
		cs.Format(_T("UdpDiscovery: auto-added friend %s"), csDesc);
		LogSendRecieveInfo(cs);
	}
}

void CUdpDiscoveryThread::SendHeartbeat()
{
	if(m_sock == INVALID_SOCKET || m_localIP.GetLength() == 0)
		return;

	CStringA csIPA = CTextConvert::UnicodeToAnsi(m_localIP);
	CStringA csNameA = CTextConvert::UnicodeToUTF8(m_computerName);

	CStringA csMsg;
	csMsg.Format("DittoHB|%s|%s", csIPA, csNameA);

	sockaddr_in broadcastAddr;
	broadcastAddr.sin_family = AF_INET;
	broadcastAddr.sin_port = htons(UDP_DISCOVERY_PORT);
	broadcastAddr.sin_addr.s_addr = inet_addr("255.255.255.255");

	int nSent = sendto(m_sock, csMsg, (int)csMsg.GetLength(), 0, (sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
	if(nSent == SOCKET_ERROR)
	{
		CString cs;
		cs.Format(_T("UdpDiscovery: sendto failed err=%d"), WSAGetLastError());
		LogSendRecieveInfo(cs);
	}
	else
	{
		CString cs;
		cs.Format(_T("UdpDiscovery: heartbeat sent (IP=%s Name=%s)"), m_localIP, m_computerName);
		LogSendRecieveInfo(cs);
	}
}

	bool CUdpDiscoveryThread::ParseHeartbeat(const char* buf, int len, CString& csIP, CString& csName)
{
	csIP = _T("");
	csName = _T("");

	if(len <= 0 || buf[0] != 'D' || buf[1] != 'i' || buf[2] != 't' || buf[3] != 't' ||
		buf[4] != 'o' || buf[5] != 'H' || buf[6] != 'B' || buf[7] != '|')
		return false;

	CStringA csIPA, csNameA;
	const char* pStart = buf + 8;
	const char* pEnd = strchr(pStart, '|');
	if(pEnd)
	{
		csIPA = CStringA(pStart, (int)(pEnd - pStart));
		csNameA = CStringA(pEnd + 1, (int)(len - (pEnd - pStart) - 1));
	}

	csIP = CTextConvert::Utf8ToUnicode(csIPA);
	csName = CTextConvert::Utf8ToUnicode(csNameA);

	return csIP.GetLength() > 0;
}

unsigned int __stdcall CUdpDiscoveryThread::ThreadFunc(void* thisptr)
{
	((CUdpDiscoveryThread*)thisptr)->Run();
	return 0;
}

void CUdpDiscoveryThread::Run()
{
	CString cs;

	WSADATA wsaData;
	int nWSA = WSAStartup(0x0202, &wsaData);
	if(nWSA != 0)
	{
		cs.Format(_T("UdpDiscovery: WSAStartup failed err=%d"), nWSA);
		LogSendRecieveInfo(cs);
		return;
	}

	m_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(m_sock == INVALID_SOCKET)
	{
		cs.Format(_T("UdpDiscovery: socket creation failed err=%d"), WSAGetLastError());
		LogSendRecieveInfo(cs);
		WSACleanup();
		return;
	}

	bool bOpt = true;
	if(setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST, (const char*)&bOpt, sizeof(bOpt)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: SO_BROADCAST failed err=%d"), WSAGetLastError());
		LogSendRecieveInfo(cs);
	}
	if(setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&bOpt, sizeof(bOpt)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: SO_REUSEADDR failed err=%d"), WSAGetLastError());
		LogSendRecieveInfo(cs);
	}

	sockaddr_in localAddr;
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(UDP_DISCOVERY_PORT);
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(m_sock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: bind failed err=%d"), WSAGetLastError());
		LogSendRecieveInfo(cs);
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
		WSACleanup();
		return;
	}

	cs.Format(_T("UdpDiscovery: listening on UDP port %d"), UDP_DISCOVERY_PORT);
	LogSendRecieveInfo(cs);

	m_localIP = GetLocalIPAddress();
	cs.Format(_T("UdpDiscovery: local IP=%s Name=%s"), m_localIP, m_computerName);
	LogSendRecieveInfo(cs);

	DWORD lastHeartbeat = GetTickCount();
	DWORD lastStartupHB = GetTickCount();
	char recvBuf[1024];

	while(m_running)
	{
		DWORD now = GetTickCount();

		// Send startup heartbeat immediately (within first 30s), then periodic every 30s
		if(now - lastStartupHB < 30000)
		{
			// First heartbeat right away on startup
			if(lastHeartbeat == lastStartupHB)
			{
				SendHeartbeat();
			}
		}

		if(now - lastHeartbeat >= UDP_DISCOVERY_INTERVAL_MS)
		{
			SendHeartbeat();
			lastHeartbeat = now;
		}

		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(m_sock, &fds);

		timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100000; // 100ms timeout

		int sel = select(0, &fds, NULL, NULL, &tv);
		if(sel > 0 && FD_ISSET(m_sock, &fds))
		{
			sockaddr_in senderAddr;
			int senderLen = sizeof(senderAddr);
			int nRecv = recvfrom(m_sock, recvBuf, sizeof(recvBuf)-1, 0, (sockaddr*)&senderAddr, &senderLen);

			if(nRecv > 0)
			{
				CString csSenderIP(CTextConvert::Utf8ToUnicode(CStringA(inet_ntoa(senderAddr.sin_addr))));

				CString csPeerIP, csPeerName;
				if(ParseHeartbeat(recvBuf, nRecv, csPeerIP, csPeerName))
                {
                    cs.Format(_T("UdpDiscovery: received from %s (peer=%s, name=%s)"), csSenderIP, csPeerIP, csPeerName);
                    LogSendRecieveInfo(cs);

                    if(csPeerIP.GetLength() > 0 && !IsIPInFriends(csPeerIP))
                    {
                        AddIPToFriends(csPeerIP);
                    }
                }
			}
		}

		Sleep(100);
	}

	closesocket(m_sock);
	m_sock = INVALID_SOCKET;
	WSACleanup();
}

void CUdpDiscoveryThread::Start()
{
	m_lock.Lock();
	if(m_threadHandle)
	{
		m_lock.Unlock();
		return;
	}

	CString cs;
	cs.Format(_T("UdpDiscovery: starting thread"));
	LogSendRecieveInfo(cs);

	m_running = true;
	m_lock.Unlock();

	m_threadHandle = (HANDLE)_beginthreadex(NULL, 0, ThreadFunc, this, 0, &m_threadId);
	if(m_threadHandle)
	{
		cs.Format(_T("UdpDiscovery: thread started id=%d"), m_threadId);
		LogSendRecieveInfo(cs);
	}
}

void CUdpDiscoveryThread::Stop()
{
	m_lock.Lock();
	if(!m_threadHandle)
	{
		m_lock.Unlock();
		return;
	}

	CString cs;
	cs.Format(_T("UdpDiscovery: stopping thread"));
	LogSendRecieveInfo(cs);

	m_running = false;

	if(m_sock != INVALID_SOCKET)
		closesocket(m_sock);
	m_sock = INVALID_SOCKET;
	m_lock.Unlock();

	DWORD dwWait = WaitForSingleObject(m_threadHandle, 3000);
	if(dwWait == WAIT_TIMEOUT)
	{
		cs.Format(_T("UdpDiscovery: thread timeout, force closing"));
		LogSendRecieveInfo(cs);
	}
	else
	{
		cs.Format(_T("UdpDiscovery: thread stopped cleanly"));
		LogSendRecieveInfo(cs);
	}

	CloseHandle(m_threadHandle);
	m_threadHandle = NULL;
	m_threadId = 0;
}
