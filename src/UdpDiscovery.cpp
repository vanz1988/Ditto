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
    ULONG hostMask = (maskBits == 32) ? 0 :
        0xFFFFFFFFUL << (32 - maskBits);
    ULONG br = ip | hostMask;
    if(br == ip)
        return _T("");

    CString cs;
    cs.Format(_T("%d.%d.%d.%d"),
        BYTE(br), BYTE(br >> 8), BYTE(br >> 16), BYTE(br >> 24));
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

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER |
        GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_INCLUDE_PREFIX |
        GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG family = AF_INET;

    DWORD size = 0;
    if(::GetAdaptersAddresses(family, flags, 0, 0, &size) != ERROR_BUFFER_OVERFLOW)
    {
        Log(_T("UdpDiscovery: GetAdaptersAddresses call 1 returned non-BUFFER_OVERFLOW"));
        return arrIPs;
    }

    BYTE* buf = new BYTE[size];
    if(buf == NULL)
    {
        Log(_T("UdpDiscovery: malloc failed"));
        return arrIPs;
    }

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
    CString csSelDesc;

    while(pAdapter)
    {
        // ipmsg filters:
        // - OperStatus == IfOperStatusUp
        // - PhysicalAddressLength > 0
        // - IfType != IF_TYPE_SOFTWARE_LOOPBACK
        // - IfType != IF_TYPE_TUNNEL
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

        cs.Format(_T("UdpDiscovery: adapter IfType=%u OperStatus=%u Desc=%s skip=%d"),
            pAdapter->IfType, pAdapter->OperStatus, csDesc, bSkip);
        Log(cs);

        if(!bSkip)
        {
            BOOL bFirst = TRUE;

            for(PIP_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
                pUnicast != NULL;
                pUnicast = pUnicast->Next)
            {
                if(pUnicast->Address.lpSockaddr->sa_family != AF_INET)
                    continue;
                if(pUnicast->Flags & IP_ADAPTER_ADDRESS_TRANSIENT)
                    continue;

                sockaddr_in* pSin = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                ULONG ip = pSin->sin_addr.S_un.S_addr;
                ULONG mask = pUnicast->OnLinkPrefixLength;

                if(mask == 0)
                    continue;

                // Skip link-local (169.254.x.x)
                ULONG ipHostOrder = ntohl(ip);
                if((ipHostOrder >> 16) == 0xA9FE)
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

                // DNS lookup for hostname
                CStringA csIPA = CTextConvert::UnicodeToAnsi(csIP);
                struct hostent* pHost = gethostbyaddr(csIPA,
                    sizeof(struct in_addr), AF_INET);
                CString csNameA;
                if(pHost && pHost->h_name)
                    csNameA = CStringA(pHost->h_name);
                if(csNameA.GetLength() > 0)
                    arrHostNames.Add(csNameA);
                else
                    arrHostNames.Add(_T(""));

                if(csBr.GetLength() > 0)
                    m_broadcasts.Add(csBr);

                if(bFirst)
                {
                    m_selectedIP = csIP;
                    m_selectedDesc = csDesc;
                    bFirst = FALSE;
                }
            }
        }
        else
        {
            // Even for skipped adapters, log any IPs for debugging
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
                    cs.Format(_T("UdpDiscovery:   [SKIP adapter] ip=%s"), csIP);
                    Log(cs);
                }
            }
        }

        pAdapter = pAdapter->Next;
    }

    delete[] buf;

    cs.Format(_T("UdpDiscovery: total %d local IP(s), %d broadcast(s)"),
        arrIPs.GetSize(), m_broadcasts.GetSize());
    Log(cs);

    for(int i = 0; i < arrIPs.GetSize(); i++)
    {
        CString csIP = arrIPs.GetAt(i);
        CString csHN = (arrHostNames.GetSize() > i) ? arrHostNames.GetAt(i) : _T("");
        CString csBr = (m_broadcasts.GetSize() > i) ? m_broadcasts.GetAt(i) : _T("");
        cs.Format(_T("UdpDiscovery:   [%d] ip=%s host=%s br=%s"),
            i, csIP, csHN, csBr);
        Log(cs);
    }

    // Store own IPs and hostnames for self-filtering
    m_ownIPs.Copy(arrIPs);
    m_ownHostNames.Copy(arrHostNames);

    if(arrIPs.GetSize() > 0)
    {
        m_selectedName = (arrHostNames.GetSize() > 0) ? arrHostNames.GetAt(0) : _T("");
        if(m_selectedName.GetLength() == 0)
            m_selectedName = m_computerName;
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
    else
    {
        CString cs;
        cs.Format(_T("UdpDiscovery: friend list full, cannot add %s"), csIP);
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
    int headerLen = (int)strlen(header);
    if(len < headerLen)
        return false;
    if(memcmp(buf, header, headerLen) != 0)
        return false;

    const char* pStart = buf + headerLen;
    int contentLen = len - headerLen;

    if(contentLen <= 0)
        return false;

    // Find name separator
    const char* pName = strchr(pStart, '|');
    CStringA csIPA, csNameA;
    if(pName)
    {
        int ipLen = (int)(pName - pStart);
        if(ipLen <= 0)
            return false;
        csIPA = CStringA(pStart, ipLen);
        csNameA = CStringA(pName + 1, contentLen - ipLen - 1);
    }
    else
    {
        csIPA = CStringA(pStart, contentLen);
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
    cs.Format(_T("UdpDiscovery: heartbeat payload len=%d"), (int)csMsg.GetLength());
    Log(cs);

    // Send to each subnet broadcast
    ULONG nBroadcasts = m_broadcasts.GetSize();
    for(ULONG i = 0; i < nBroadcasts; i++)
    {
        CString csBr = m_broadcasts.GetAt(i);
        CStringA csBrA = CTextConvert::UnicodeToAnsi(csBr);

        ULONG ulBr = inet_addr(csBrA);
        if(ulBr == INADDR_NONE)
        {
            cs.Format(_T("UdpDiscovery: invalid broadcast addr %s"), csBr);
            Log(cs);
            continue;
        }

        sockaddr_in sendAddr;
        ::ZeroMemory(&sendAddr, sizeof(sendAddr));
        sendAddr.sin_family = AF_INET;
        sendAddr.sin_port = htons(UDP_DISCOVERY_PORT);
        sendAddr.sin_addr.S_un.S_addr = ulBr;

        int nSent = ::sendto(m_sock, csMsg, (int)csMsg.GetLength(), 0,
            (sockaddr*)&sendAddr, sizeof(sendAddr));

        if(nSent == SOCKET_ERROR)
        {
            cs.Format(_T("UdpDiscovery: sendto br=%s failed err=%d"),
                csBr, WSAGetLastError());
            Log(cs);
        }
        else
        {
            cs.Format(_T("UdpDiscovery: sendto br=%s OK"), csBr);
            Log(cs);
        }
    }

    // Fallback: 255.255.255.255
    sockaddr_in sendAddr;
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
    m_ownIPs.RemoveAll();
    m_ownHostNames.RemoveAll();
    m_broadcasts.RemoveAll();

    m_computerName = GetComputerNameSafe();
    m_userName = GetUsernameSafe();
    DiscoverLocalIPs();

    cs.Format(_T("UdpDiscovery: selected IP=%s Name=%s"),
        m_selectedIP, m_selectedName);
    Log(cs);

    if(m_ownIPs.GetSize() == 0)
    {
        cs.Format(_T("UdpDiscovery: WARNING - no valid IP, heartbeat disabled"));
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
                    cs.Format(_T("UdpDiscovery: skipped own HB from %s"), csSenderIP);
                    Log(cs);
                    continue;
                }

                CString csPeerIP, csPeerName;
                if(ParseHeartbeat(recvBuf, nRecv, csPeerIP, csPeerName))
                {
                    cs.Format(_T("UdpDiscovery: recv from %s (peer=%s name=%s)"),
                        csSenderIP, csPeerIP, csPeerName);
                    Log(cs);

                    if(csPeerIP.GetLength() > 0 && !IsIPInFriends(csPeerIP))
                    {
                        AddIPToFriends(csPeerIP, csPeerName);
                    }
                }
                else
                {
                    cs.Format(_T("UdpDiscovery: recv %d bytes from %s, not heartbeat"),
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
