#pragma once

#include "RecieveSocket.h"
#include "FileTransferProgressDlg.h"

#define USER_CANCELED -2
#define MD5_MISMATCH -3

class CFileRecieve
{
public:
	CFileRecieve();
	virtual ~CFileRecieve();

	long RecieveFiles(SOCKET sock, CString csIP, CFileTransferProgressDlg *pProgress, LPCTSTR csDestDir = NULL);
	
	HGLOBAL CreateCF_HDROPBuffer();

	HGLOBAL CreateCF_HDROPBufferAsString();

	void AddFile(CString csFile)	{ m_RecievedFiles.Add(csFile); }

protected:
	long RecieveFileData(ULONG lFileSize, CString csFileName, CString &md5String, LPCTSTR csDestDir = NULL);

protected:
	CRecieveSocket m_Sock;
	CString m_csReceivingFromIP;
	CString m_csDestDir;  // target directory from foreground explorer (empty = fallback to ReceivedFiles)
	CStringArray m_RecievedFiles;
	CFileTransferProgressDlg *m_pProgress;
};
