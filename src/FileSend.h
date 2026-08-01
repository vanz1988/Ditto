#pragma once

#include "SendSocket.h"

class CFileSend  
{
public:
	CFileSend();
	virtual ~CFileSend();

	BOOL SendClientFiles(SOCKET sock, CClipList *pClipList);
	BOOL SendFile(CString csFile, LPCTSTR csRelPath = NULL);
	BOOL SendDir(CString csRelPath);
	void EnumerateDirectory(CString csDir, LPCTSTR csPrefix, CStringArray &rDirs, CStringArray &rAbsFiles, CStringArray &rRelFiles);

	protected:
	CClipFormat* GetCF_HDROP_Data(CClipList *pClipList);

protected:
	CSendSocket m_Send;
};
