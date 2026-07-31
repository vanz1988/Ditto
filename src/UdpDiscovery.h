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
    CString m_computerName;
    CString m_userName;

    CStringArray m_ownIPs;         // All own IPs for self-filtering
    CStringArray m_ownHostNames;   // Hostnames for each IP
    CStringArray m_broadcasts;     // Subnet broadcast per interface
    CString m_selectedIP;          // Primary IP for heartbeat payload
    CString m_selectedName;        // Primary hostname
    CString m_selectedDesc;        // Primary adapter description

    ULONG IPv4ToUlong(const CString& csIP);
    CString MakeBroadcastAddr(ULONG ip, ULONG maskBits);
    CString GetUsernameSafe();
    CString GetComputerNameSafe();
    bool IsIPInFriends(const CString& csIP);
    void AddIPToFriends(const CString& csIP, const CString& csName);
    bool ParseHeartbeat(const char* buf, int len, CString& ip, CString& name);
    void SendHeartbeat();
    CStringArray DiscoverLocalIPs();
    bool SetupWSA();
    bool SetupSocket();
};
