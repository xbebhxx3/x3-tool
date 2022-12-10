/**************************************
@brief           x3-tool
@license         GPLv3
@version          6.0
@remarks          编译时加 -std=gnu++11 -lgdi32 -lwsock32
@author           xbehxx3
@date             2022/6/14
Copyright (c) 2022-2077 xbebhxx3
***************************************/
#include "x3-f.h"
#include <iostream>

char in[1000], gn[1000];
DWORD InId;

BOOL ListProcessModules(DWORD dwPID)
{ //列出进程模块
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID); //获得快照
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32))
	{							  //获得进程模块信息
		CloseHandle(hModuleSnap); // 关闭快照
		return (FALSE);
	}
	do
	{ //显示
		printf("\n\n     模块名:    %s", me32.szModule);
		printf("\n     路径       = %s", me32.szExePath);
		printf("\n     进程id     = %d", me32.th32ProcessID);
		printf("\n     模块加载数 = 0x%04X", me32.GlblcntUsage);
		printf("\n     模块地址   = 0x%08X", me32.modBaseAddr);
		printf("\n     模块大小   = %d", me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
	return (TRUE);
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{ //列出进程线程
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); //获得快照
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap); // 关闭快照
		return (FALSE);
	}
	do
	{ //显示线程信息
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			printf("\n\n         线程id     = %d", te32.th32ThreadID);
			printf("\n         优先级     = %d", te32.tpBasePri);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return (TRUE);
}
BOOL GetProcessList()
{ //获得进程列表
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //获得快照
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return (FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{							   //获得进程信息
		CloseHandle(hProcessSnap); // 关闭快照
		return (FALSE);
	}
	do
	{ //显示
		printf("\n\n=====================================================");
		printf("\n进程名:  %s", pe32.szExeFile);
		printf("\n-----------------------------------------------------");

		dwPriorityClass = 0;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		dwPriorityClass = GetPriorityClass(hProcess); // 检索优先级
		CloseHandle(hProcess);

		printf("\n 进程id   = %d", pe32.th32ProcessID);
		printf("\n 线程数量 = %d", pe32.cntThreads);
		printf("\n 父进程id = %d", pe32.th32ParentProcessID);
		printf("\n 优先级   = %d", pe32.pcPriClassBase);
		if (dwPriorityClass)
			printf("\n 优先级   = %d", dwPriorityClass);

		ListProcessModules(pe32.th32ProcessID); //获得进程模块信息
		ListProcessThreads(pe32.th32ProcessID); //获得进程线程信息
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return (TRUE);
}

int main(int argc, char **argv)
{
	EnableAllPrivilege();
	if (argc == 1)
	{
		printf("x3-tool v6.0\n输入h获得帮助\n");
	input:
		printf("\n>");
		cin.sync();
		cin >> gn;
	}
	else
	{
		strcpy(gn, argv[1]);
	}
	if (lstrcmp(gn, "ia") == 0)
	{
		printf("%d", IsProcessRunAsAdmin());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "ua") == 0)
	{
		if (argc == 3)
			printf("%d", ShellExecute(NULL, "runas", argv[2], NULL, NULL, SW_SHOW));
		else
		{
			printf("[+] 文件路径：");
			cin.sync(); //清空输入缓冲区
			scanf("%[^\n]", &in);
			printf("%d", ShellExecute(NULL, "runas", in, NULL, NULL, SW_SHOW));
			goto input;
		}
	}
	else if (lstrcmp(gn, "us") == 0)
	{
		if (argc == 3)
			printf("%d", UseSystem(argv[2]));
		else
		{
			printf("[+] 文件路径：");
			cin.sync(); //清空输入缓冲区
			scanf("%[^\n]", &in);
			printf("%d", UseSystem(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "ut") == 0)
	{
		if (argc == 3)
			printf("%d", UseTrustedInstaller(argv[2]));
		else
		{
			printf("[+] 文件路径：");
			cin.sync(); //清空输入缓冲区
			scanf("%[^\n]", &in);
			printf("%d", UseTrustedInstaller(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "ra") == 0)
	{
		printf("%d", RunAsAdmin());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "rt") == 0)
	{
		printf("%d", RunAsTi());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "kp") == 0)
	{
		if (argc == 3)
			printf("%d", KillProcess(atoi(argv[2])));
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			printf("%d", KillProcess(InId));
			goto input;
		}
	}
	else if (lstrcmp(gn, "ip") == 0)
	{
		if (argc == 3)
			printf("%d", isProcess(argv[2]));
		else
		{
			printf("[+] 进程名: ");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%d", isProcess(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "gpl") == 0)
	{
		if (argc == 3)
			printf("%s", GetProcesslocation(atoi(argv[2])));
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			printf("%s", GetProcesslocation(InId));
			goto input;
		}
	}
	else if (lstrcmp(gn, "sp") == 0)
	{
		if (argc == 4)
		{
			if (lstrcmp(argv[3], "1") == 0)
				printf("%d", SuspendProcess(atoi(argv[2]), 1));
			else
				printf("%d", SuspendProcess(atoi(argv[2]), 0));
		}
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			printf("[+] 1挂起0解除: ");
			cin.sync();
			scanf("%[^\n]", &in);
			if (lstrcmp(in, "1") == 0)
				printf("%d", SuspendProcess(InId, 1));
			else
				printf("%d", SuspendProcess(InId, 0));
			goto input;
		}
	}
	else if (lstrcmp(gn, "cp") == 0)
	{
		if (argc == 4)
		{
			if (lstrcmp(argv[3], "1") == 0)
				printf("%d", CriticalProcess(atoi(argv[2]), 1));
			else
				printf("%d", CriticalProcess(atoi(argv[2]), 0));
		}
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			printf("[+] 1设置0解除: ");
			cin.sync();
			scanf("%[^\n]", &in);
			if (lstrcmp(in, "1") == 0)
				printf("%d", CriticalProcess(InId, 1));
			else
				printf("%d", CriticalProcess(InId, 0));
			goto input;
		}
	}
	else if (lstrcmp(gn, "cs") == 0)
	{
		if (argc == 3)
		{
			printf("%d", CloseService(argv[2]));
		}
		else
		{
			printf("[+] 服务名：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%d", CloseService(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "ss") == 0)
	{
		if (argc == 3)
		{
			printf("%d", _StartService(argv[2]));
		}
		else
		{
			printf("[+] 服务名：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%d", _StartService(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "ls") == 0)
	{
		ListService();
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "lpm") == 0)
	{
		if (argc == 3)
			ListProcessModules(atoi(argv[2]));
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			ListProcessModules(InId);
			goto input;
		}
	}
	else if (lstrcmp(gn, "lpt") == 0)
	{
		if (argc == 3)
			ListProcessThreads(atoi(argv[2]));
		else
		{
			printf("[+] 进程ID: ");
			cin.sync();
			scanf("%d", &InId);
			ListProcessThreads(InId);
			goto input;
		}
	}
	else if (lstrcmp(gn, "lp") == 0)
	{
		GetProcessList();
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "cu") == 0)
	{
		if (argc == 3)
			printf("%s", CodeUrl(argv[2]).c_str());
		else
		{
			printf("[+] 输入字符串：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%s", CodeUrl(in).c_str());
			goto input;
		}
	}
	else if (lstrcmp(gn, "du") == 0)
	{
		if (argc == 3)
			printf("%s", DecodeUrl(argv[2]).c_str());
		else
		{
			printf("[+] 输入字符串：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%s", DecodeUrl(in).c_str());
			goto input;
		}
	}
	else if (lstrcmp(gn, "xc") == 0)
	{
		if (argc == 3)
			printf("%s", x3code(argv[2]));
		else
		{
			printf("[+] 输入字符串：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("%s", x3code(in));
			goto input;
		}
	}
	else if (lstrcmp(gn, "lkm") == 0)
	{
		if (argc == 3)
		{
			if (lstrcmp(argv[2], "1") == 0)
				printf("%d", lockkm(1));
			else
				printf("%d", lockkm(0));
		}
		else
		{
			printf("[+] 1锁定0解除: ");
			cin.sync();
			scanf("%[^\n]", &in);
			if (lstrcmp(in, "1") == 0)
				printf("%d", lockkm(1));
			else
				printf("%d", lockkm(0));
			goto input;
		}
	}
	else if (lstrcmp(gn, "rs") == 0)
	{
		if (argc == 3)
			printf("%s", getCmdResult(argv[2]));
		else
		{
			printf("[+] 输入exit退出\n");
			while (1)
			{
				printf("shell>");
				cin.sync();
				scanf("%[^\n]", &in);
				if (lstrcmp(in, "exit") == 0)
					goto input;
				printf("%s", getCmdResult(in));
			}
		}
	}
	else if (lstrcmp(gn, "mxy") == 0)
	{
		int x, y;
		mouxy(x, y);
		printf("X:%d\nY:%d", x, y);
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "cls") == 0)
	{
		cls();
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "gi") == 0)
	{
		printf("%s", getIp());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "gu") == 0)
	{
		printf("%s", GetUser());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "gv") == 0)
	{
		printf("%s", GetSystemVersion());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "om") == 0)
	{
		if (argc == 4)
		{
			OutoutMiddle(argv[2], atoi(argv[3]));
		}
		else
		{
			printf("[+] 字符串：");
			cin.sync();
			scanf("%[^\n]", &in);
			printf("[+] 行数：");
			cin.sync();
			scanf("%d", &InId);
			OutoutMiddle(in, InId);
			goto input;
		}
	}
	else if (lstrcmp(gn, "fc") == 0)
	{
		full_screen(GetForegroundWindow());
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "rn") == 0)
	{
		if (argc == 4)
		{
			radom(atoi(argv[2]), atoi(argv[3]));
		}
		else
		{
			long long min,max;
			printf("[+] 开始: ");
			cin.sync();
			scanf("%lld", &min);
			printf("[+] 结束: ");
			cin.sync();
			scanf("%lld", &max);
			printf("%lld", radom(min, max));
			goto input;
		}
	}
	else if (lstrcmp(gn, "exit") == 0)
	{
		exit;
	}
	else if (lstrcmp(gn, "v") == 0)
	{
		printf("v6.0\n");
		if (argc != 2)
			goto input;
	}
	else if (lstrcmp(gn, "h") == 0)
	{
		printf("示例：x3-tool.exe [功能] ([值])\n");
		printf("一个超小体积的强大的windows命令行工具-x3tool  v6.0\n");
		printf("支持直接运行/命令行调用\n");
		printf("无返回值的返回0均为失败1均为成功\n");
		printf("邮件:admin@n103.top\n");
		printf("官网:www.n103.top\n");
		printf("           by:  xbebhxx3\n\n");
		printf("x3-tool\n");
		printf("|- 权限操作                                     \n");
		printf("|    |- 判断管理员权限  1有 0无             (ia)\n");
		printf("|    |- 以管理员权限打开                    (ua)\n");
		printf("|    |- 以system权限打开                    (us)\n");
		printf("|    |- 以TrustedInstaller权限打开          (ut)\n");
		printf("|    |- 以administrator权限重启工具         (ra)\n");
		printf("|    |- 以TrustedInstaller权限重启工具      (rt)\n");
		printf("|- 进程操作                                     \n");
		printf("|   |- 结束进程                             (kp)\n");
		printf("|   |- 判断进程是否存在 ,并返回进程id       (ip)\n");
		printf("|   |- 获得进程路径                         (gpl)\n");
		printf("|   |- 挂起进程                             (sp)\n");
		printf("|   |- 设置关键进程                         (cp)\n");
		printf("|   |- 停止服务                             (cs)\n");
		printf("|   |- 启动服务                             (ss)\n");
		printf("|   |- 列出所有服务                         (ls)\n");
		printf("|   |- 列出进程模块                         (lpm)\n");
		printf("|   |- 列出进程线程                         (lpt)\n");
		printf("|   |- 列出所有进程详细信息                 (lp)\n");
		printf("|- 编/解码操作                                  \n");
		printf("|      |- Url编码                           (cu)\n");
		printf("|      |- Url解码                           (du)\n");
		printf("|      |- 简易加密                          (xc)\n");
		printf("|- 锁定鼠标键盘                             (lkm)\n");
		printf("|- 执行shell命令                            (rs)\n");
		printf("|- 获得鼠标位置                             (mxy)\n");
		printf("|- 清屏                                     (cls)\n");
		printf("|- 获得当前ip                               (gi)\n");
		printf("|- 获得当前用户名                           (gu)\n");
		printf("|- 获得系统版本                             (gv)\n");
		printf("|- 居中输出                                 (om)\n");
		printf("|- 真·全屏                                 (fc)\n");
		printf("|- 随机数                                   (rn)\n");
		printf("|- 帮助                                     (h)\n");
		printf("|- 版本                                     (v)\n\n");
		printf("命令行示例: x3-tool.exe sp 10010 1\n");
		printf("示例: kp\n\n");
		goto input;
	}
	else
	{
		printf("输入错误\n");
		goto input;
	}
}
