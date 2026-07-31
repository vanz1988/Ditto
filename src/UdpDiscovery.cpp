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
	m_computerName = _T("");
	m_userName = _T("");
	m_selectedIP = _T("");
	m_selectedName = _T("");
	m_selectedDesc = _T("");
}

CUdpDiscoveryThread::~CUdpDiscoveryThread()
{
	Stop();
}

CString CUdpDiscoveryThread::GetComputerNameSafe()
{
	CString cs;
	TCHAR szName[256];
	DWORD dwLen = 256;
	if(GetComputerName(szName, &dwLen))
		cs = szName;
	else
		cs = _T("Ditto");
	return cs;
}

CString CUdpDiscoveryThread::GetUsernameSafe()
{
	CString cs;
	TCHAR szUser[256];
	DWORD dwLen = 256;
	if(GetUserName(szUser, &dwLen))
		cs = szUser;
	else
		cs = _T("user");
	return cs;
}

ULONG CUdpDiscoveryThread::IPv4ToUlong(const CString& csIP)
{
	ULONG ul = 0;
	CStringA csA = CTextConvert::UnicodeToAnsi(csIP);
	struct in_addr addr;
	if(::inet_pton(AF_INET, csA, &addr) == 1)
		ul = addr.S_un.S_addr;
	else
		ul = inet_addr(csA);
	return ul;
}

CString CUdpDiscoveryThread::MakeBroadcastAddr(ULONG ip, ULONG maskBits)
{
	ULONG hostMask = (maskBits == 32) ? 0xFFFFFFFFUL :
		0xFFFFFFFFUL << (32 - maskBits);
	ULONG netMask = ~hostMask;
	ULONG br = ip | hostMask;
	// If broadcast == ip (point-to-point like /32), skip
	if(br == ip)
		return _T("");

	CString cs;
	cs.Format(_T("%lu.%lu.%lu.%lu"),
		BYTE(br >> 24), BYTE((br >> 16) & 0xFF),
		BYTE((br >> 8) & 0xFF), BYTE(br & 0xFF));
	return cs;
}

bool CUdpDiscoveryThread::SetupWSA()
{
	WSADATA wsaData;
	int nRet = WSAStartup(0x0202, &wsaData);
	CString cs;
	if(nRet != 0)
	{
		cs.Format(_T("UdpDiscovery: WSAStartup failed err=%d"), nRet);
		Log(cs);
		return false;
	}
	cs.Format(_T("UdpDiscovery: WSAStartup OK (version %u.%u)"),
		LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
	Log(cs);
	return true;
}

bool CUdpDiscoveryThread::SetupSocket()
{
	m_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
	CString cs;
	if(m_sock == INVALID_SOCKET)
	{
		cs.Format(_T("UdpDiscovery: socket creation failed err=%d"), WSAGetLastError());
		Log(cs);
		return false;
	}

	BOOL bOpt = TRUE;
	if(::setsockopt(m_sock, SOL_SOCKET, SO_BROADCAST,
		(const char*)&bOpt, sizeof(bOpt)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: SO_BROADCAST failed err=%d"), WSAGetLastError());
		Log(cs);
	}
	if(::setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR,
		(const char*)&bOpt, sizeof(bOpt)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: SO_REUSEADDR failed err=%d"), WSAGetLastError());
		Log(cs);
	}

	sockaddr_in localAddr;
	::ZeroMemory(&localAddr, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(UDP_DISCOVERY_PORT);
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(::bind(m_sock, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: bind failed err=%d"), WSAGetLastError());
		Log(cs);
		::closesocket(m_sock);
		m_sock = INVALID_SOCKET;
		return false;
	}

	cs.Format(_T("UdpDiscovery: listening on UDP port %d"), UDP_DISCOVERY_PORT);
	Log(cs);
	return true;
}

// ── ipmsg-style adapter enumeration using GetAdaptersAddresses ──────────────

CStringArray CUdpDiscoveryThread::DiscoverLocalIPs()
{
	CStringArray arrIPs;
	CStringArray arrHostNames;
	CStringArray arrBroadcasts;

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER |
		GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_PREFIX |
		GAA_FLAG_INCLUDE_GATEWAYS;
	ULONG family = AF_INET;

	DWORD size = 0;
	if(::GetAdaptersAddresses(family, flags, 0, 0, &size) != ERROR_BUFFER_OVERFLOW)
		return arrIPs;

	BYTE* buf = new BYTE[size];
	if(buf == NULL)
		return arrIPs;

	ULONG ret = ::GetAdaptersAddresses(family, flags, 0,
		(PIP_ADAPTER_ADDRESSES)buf, &size);

	CString cs;
	cs.Format(_T("UdpDiscovery: GetAdaptersAddresses ret=%u"), ret);
	Log(cs);

	if(ret != ERROR_SUCCESS)
	{
		delete[] buf;
		return arrIPs;
	}

	PIP_ADAPTER_ADDRESSES pAdapter = (PIP_ADAPTER_ADDRESSES)buf;
	int nIdx = 0;
	CString csAll;

	while(pAdapter && nIdx < 200)
	{
		// ipmsg filters: OperStatus==Up, PhysicalAddressLength>0, not loopback
		BOOL bSkip = FALSE;
		if(pAdapter->OperStatus != IfOperStatusUp)
			bSkip = TRUE;
		else if(pAdapter->PhysicalAddressLength <= 0)
			bSkip = TRUE;
		else if(pAdapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			bSkip = TRUE;
		else if(pAdapter->IfType == IF_TYPE_TUNNEL)
			bSkip = TRUE;

		CString csDesc;
		if(pAdapter->Description)
			csDesc = pAdapter->Description;
		else
			csDesc = _T("(unknown)");

		cs.Format(_T("UdpDiscovery: adapter[%d] IfType=%u OperStatus=%u Desc=%s skip=%d"),
			nIdx, pAdapter->IfType, pAdapter->OperStatus, csDesc, bSkip);
		Log(cs);

		if(!bSkip)
		{
			ULONG selectedIP = 0;
			ULONG selectedMask = 0;
			CString csSelDesc;

			for(PIP_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
			    pUnicast != NULL && nIdx < 200;
			    pUnicast = pUnicast->Next)
            {
                if(!(pUnicast->Address.lpSockaddr->sa_family == AF_INET))
                    continue;
                if(pUnicast->Flags & IP_ADAPTER_ADDRESS_TRANSIENT)
                    continue;

                sockaddr_in* pSin = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                ULONG ip = pSin->sin_addr.S_un.S_addr;
                ULONG mask = pUnicast->OnLinkPrefixLength;

                if(mask == 0)
                    continue;

                // Skip link-local (169.254.x.x)
                if((ip >> 16) == htonl(0xA9FE))
                {
                    cs.Format(_T("UdpDiscovery:   SKIP 169.254.x.x"));
                    Log(cs);
                    continue;
                }

                CString csIP;
                csIP.Format(_T("%d.%d.%d.%d"),
                    BYTE(ip), BYTE(ip >> 8), BYTE(ip >> 16), BYTE(ip >> 24));

                CString csBr = MakeBroadcastAddr(ip, mask);

                cs.Format(_T("UdpDiscovery:   VALID ip=%s mask=/ %u br=%s"),
                    csIP, mask, csBr);
                Log(cs);

                arrIPs.Add(csIP);
                CString csHN;
                if(arrHostNames.GetSize() > 0 && nIdx < arrHostNames.GetSize())
                    csHN = arrHostNames.GetAt(arrHostNames.GetSize()-1);
                else
                    csHN = _T("");
                arrHostNames.Add(_T(""));

                // DNS lookup for hostname
                CStringA csIPA = CTextConvert::UnicodeToAnsi(csIP);
                struct hostent* pHost = gethostbyaddr(csIPA, sizeof(struct in_addr), AF_INET);
                CString csNameA;
                if(pHost && pHost->h_name)
                    csNameA = CStringA(pHost->h_name);
                if(csNameA.GetLength() > 0)
                    arrHostNames.SetAt(arrHostNames.GetSize() - 1, csNameA);

                arrBroadcasts.Add(csBr);

                // Keep first valid IP as selected (primary)
                if(selectedIP == 0)
                {
                    selectedIP = ip;
                    selectedMask = mask;
                    csSelDesc = csDesc;
                }

                nIdx++;
            }
		}
		else
		{
			// Even for skipped adapters, log any IPs
			for(PIP_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
			    pUnicast != NULL;
			    pUnicast = pUnicast->Next)
            {
                if(pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                {
                    sockaddr_in* pSin = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    ULONG ip = pSin->sin_addr.S_un.S_addr;
                    CString csIP;
                    csIP.Format(_T("%d.%d.%d.%d"),
                        BYTE(ip), BYTE(ip >> 8), BYTE(ip >> 16), BYTE(ip >> 24));
                    cs.Format(_T("UdpDiscovery:   [SKIP] ip=%s desc=%s"), csIP, csDesc);
                    Log(cs);
                }
            }
		}

		pAdapter = pAdapter->Next;
	}

	delete[] buf;

	CStringArray arrDescs;
	cs.Format(_T("UdpDiscovery: found %d interface(s): "), arrIPs.GetSize());
	Log(cs);
	for(int i = 0; i < arrIPs.GetSize(); i++)
	{
		CString csIP = arrIPs.GetAt(i);
		CString csHN = (arrHostNames.GetSize() > i) ? arrHostNames.GetAt(i) : _T("");
		CString csBr = (arrBroadcasts.GetSize() > i) ? arrBroadcasts.GetAt(i) : _T("");
		cs.Format(_T("UdpDiscovery:   [%d] ip=%s host=%s br=%s"),
			i, csIP, csHN, csBr);
		Log(cs);
	}

	if(arrIPs.GetSize() > 0)
	{
		m_selectedIP = arrIPs.GetAt(0);
		m_selectedName = (arrHostNames.GetSize() > 0) ? arrHostNames.GetAt(0) : _T("");
		m_selectedDesc = csSelDesc;
	}

	return arrIPs;
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

void CUdpDiscoveryThread::AddIPToFriends(const CString& csIP, const CString& csName)
{
	CString csDesc;
	if(csName.GetLength() > 0)
		csDesc.Format(_T("%s (%s)"), csName, csIP);
	else
		csDesc = csIP;

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
		Log(cs);
	}
}

bool CUdpDiscoveryThread::ParseHeartbeat(const char* buf, int len,
	CString& csIP, CString& csName)
{
	csIP = _T("");
	csName = _T("");

	if(len <= 0)
		return false;

	// Validate magic header "DittoHB|"
	const char* header = "DittoHB|";
	if(len < (int)strlen(header))
		return false;
	if(memcmp(buf, header, strlen(header)) != 0)
		return false;

	const char* pStart = buf + strlen(header);
	int contentLen = len - (int)strlen(header);

	if(contentLen <= 0)
		return false;

	CStringA csMsgA(pStart, contentLen);

	const char* pName = strchr(pStart, '|');
	CStringA csIPA, csNameA;
	if(pName)
	{
		int ipLen = (int)(pName - pStart);
		csIPA = CStringA(pStart, ipLen);
		csNameA = CStringA(pName + 1, (int)(contentLen - ipLen - 1));
	}
	else
	{
		csIPA = csMsgA;
	}

	csIP = CTextConvert::Utf8ToUnicode(csIPA);
	csName = CTextConvert::Utf8ToUnicode(csNameA);

	return csIP.GetLength() > 0;
}

void CUdpDiscoveryThread::SendHeartbeat()
{
	if(m_sock == INVALID_SOCKET)
		return;
	if(m_selectedIP.GetLength() == 0)
		return;

	CStringA csIPA = CTextConvert::UnicodeToAnsi(m_selectedIP);
	CStringA csNameA = CTextConvert::UnicodeToUTF8(m_computerName);

	CStringA csMsg;
	csMsg.Format("DittoHB|%s|%s", csIPA, csNameA);

	CString cs;
	cs.Format(_T("UdpDiscovery: heartbeat payload=%s"), csMsg);
	Log(cs);

	sockaddr_in sendAddr;
	ULONG nBroadcasts = m_broadcasts.GetSize();

	for(ULONG i = 0; i < nBroadcasts; i++)
	{
		CString csBr = m_broadcasts.GetAt(i);
		CStringA csBrA = CTextConvert::UnicodeToAnsi(csBr);

		ULONG ulBr = inet_addr(csBrA);
		if(ulBr == INADDR_NONE)
			continue;

		::ZeroMemory(&sendAddr, sizeof(sendAddr));
		sendAddr.sin_family = AF_INET;
		sendAddr.sin_port = htons(UDP_DISCOVERY_PORT);
		sendAddr.sin_addr.S_un.S_addr = ulBr;

		int nSent = ::sendto(m_sock, csMsg, (int)csMsg.GetLength(), 0,
			(sockaddr*)&sendAddr, sizeof(sendAddr));

		CStringA csBrA2 = csBrA;
		if(nSent == SOCKET_ERROR)
		{
			cs.Format(_T("UdpDiscovery: sendto br=%s failed err=%d"),
				csBr, WSAGetLastError());
			Log(cs);
		}
		else
		{
			cs.Format(_T("UdpDiscovery: sendto br=%s OK (len=%d)"),
				csBr, nSent);
			Log(cs);
		}
	}

	// Fallback: also send to 255.255.255.255
	ULONG nSentAll = 0;
	::ZeroMemory(&sendAddr, sizeof(sendAddr));
	sendAddr.sin_family = AF_INET;
	sendAddr.sin_port = htons(UDP_DISCOVERY_PORT);
	sendAddr.sin_addr.S_un.S_addr = htonl(INADDR_BROADCAST);

	int nSent = ::sendto(m_sock, csMsg, (int)csMsg.GetLength(), 0,
		(sockaddr*)&sendAddr, sizeof(sendAddr));
	if(nSent == SOCKET_ERROR)
	{
		cs.Format(_T("UdpDiscovery: sendto 255.255.255.255 failed err=%d"),
			WSAGetLastError());
		Log(cs);
	}
	else
	{
		cs.Format(_T("UdpDiscovery: sendto 255.255.255.255 OK"));
		Log(cs);
	}
}

// ── Main thread loop ──────────────────────────────────────────────────────

unsigned int __stdcall CUdpDiscoveryThread::ThreadFunc(void* thisptr)
{
	((CUdpDiscoveryThread*)thisptr)->Run();
	return 0;
}

void CUdpDiscoveryThread::Run()
{
	CString cs;

	// Phase 1: Setup WSA
	if(!SetupWSA())
	{
		Log(_T("UdpDiscovery: WSAStartup failed, aborting"));
		return;
	}

	// Phase 2: Setup socket
	if(!SetupSocket())
	{
		Log(_T("UdpDiscovery: socket setup failed, aborting"));
		WSACleanup();
		return;
	}

	// Phase 3: Enumerate local IPs
	m_ownIPs = DiscoverLocalIPs();

	cs.Format(_T("UdpDiscovery: selected IP=%s Name=%s User=%s"),
		m_selectedIP, m_selectedName, m_userName);
	Log(cs);

	if(m_ownIPs.GetSize() == 0)
	{
		cs.Format(_T("UdpDiscovery: WARNING - no valid IP found, heartbeat disabled"));
		Log(cs);
	}

	DWORD lastHeartbeat = GetTickCount();
	char recvBuf[1024];

	cs.Format(_T("UdpDiscovery: thread loop started, %d local IP(s)"), m_ownIPs.GetSize());
	Log(cs);

	while(m_running)
	{
		DWORD now = GetTickCount();

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
		tv.tv_usec = 100000;

		int sel = select(0, &fds, NULL, NULL, &tv);
		if(sel > 0 && FD_ISSET(m_sock, &fds))
		{
			sockaddr_in senderAddr;
			int senderLen = sizeof(senderAddr);
			int nRecv = ::recvfrom(m_sock, recvBuf, sizeof(recvBuf) - 1,
				0, (sockaddr*)&senderAddr, &senderLen);

			if(nRecv > 0)
			{
                CString csSenderIP(CTextConvert::Utf8ToUnicode(
                    CStringA(inet_ntoa(senderAddr.sin_addr))));

				// Self-filter: skip if sender is one of our own IPs
				BOOL bSelf = FALSE;
                for(int i = 0; i < m_ownIPs.GetSize(); i++)
                {
                    if(csSenderIP == m_ownIPs.GetAt(i))
                    {
                        bSelf = TRUE;
                        break;
                    }
                }

				if(bSelf)
				{
					cs.Format(_T("UdpDiscovery: skipped own heartbeat from %s"), csSenderIP);
					Log(cs);
					continue;
				}

				CString csPeerIP, csPeerName;
				if(ParseHeartbeat(recvBuf, nRecv, csPeerIP, csPeerName))
                {
                    cs.Format(_T("UdpDiscovery: received from %s (peer=%s name=%s)"),
                        csSenderIP, csPeerIP, csPeerName);
                    Log(cs);

                    if(csPeerIP.GetLength() > 0 && !IsIPInFriends(csPeerIP))
                    {
                        AddIPToFriends(csPeerIP, csPeerName);
                    }
                }
                else
                {
                    cs.Format(_T("UdpDiscovery: recv %d bytes from %s, not a heartbeat"),
                        nRecv, csSenderIP);
                    Log(cs);
                }
			}
		}

		Sleep(100);
	}

	::closesocket(m_sock);
	m_sock = INVALID_SOCKET;
	WSACleanup();
	cs.Format(_T("UdpDiscovery: thread loop ended"));
	Log(cs);
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
	Log(cs);

	m_computerName = GetComputerNameSafe();
	m_userName = GetUsernameSafe();

	m_running = true;
	m_lock.Unlock();

	m_threadHandle = (HANDLE)_beginthreadex(NULL, 0, ThreadFunc, this, 0, &m_threadId);
	if(m_threadHandle)
	{
		cs.Format(_T("UdpDiscovery: thread started id=%u"), m_threadId);
		Log(cs);
	}
	else
	{
		cs.Format(_T("UdpDiscovery: thread start failed err=%d"), GetLastError());
		Log(cs);
		m_running = false;
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
	Log(cs);

	m_running = false;

	if(m_sock != INVALID_SOCKET)
	{
		::closesocket(m_sock);
		m_sock = INVALID_SOCKET;
	}

	m_lock.Unlock();

	DWORD dwWait = WaitForSingleObject(m_threadHandle, 3000);
	if(dwWait == WAIT_TIMEOUT)
	{
		cs.Format(_T("UdpDiscovery: thread timeout, force closing"));
		Log(cs);
	}
	else
	{
		cs.Format(_T("UdpDiscovery: thread stopped cleanly"));
		Log(cs);
	}

	if(m_threadHandle)
	{
		CloseHandle(m_threadHandle);
		m_threadHandle = NULL;
		m_threadId = 0;
	}
}
