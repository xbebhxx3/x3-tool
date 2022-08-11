/************************************** 
@brief 			 x3-tool
@license: 		 GPLv3 
@version  	     3.0
@remarks         ����ʱ�� -std=gnu++11 -lgdi32 -lwsock32
@author          xbehxx3
@date            2022/6/14
Copyright (c) 2022-2077 xbebhxx3
***************************************/
#include "x3-f.h" 

char in[1000],gn[1000];

BOOL ListProcessModules(DWORD dwPID){ //�г�����ģ��
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID); //��ÿ���
	if (hModuleSnap == INVALID_HANDLE_VALUE)return (FALSE);

	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32)){                            //��ý���ģ����Ϣ
		CloseHandle(hModuleSnap); // �رտ���
		return (FALSE);
	}
	do{ //��ʾ
	    printf("\n\n     ģ����:    %s", me32.szModule);
	    printf("\n     ·��       = %s", me32.szExePath);
	    printf("\n     ����id     = %d", me32.th32ProcessID);
	    printf("\n     ģ������� = 0x%04X", me32.GlblcntUsage);
	    printf("\n     ģ���ַ   = 0x%08X", me32.modBaseAddr);
		printf("\n     ģ���С   = %d", me32.modBaseSize);

	}
	while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
	return (TRUE);
}

BOOL ListProcessThreads(DWORD dwOwnerPID){//�г������߳�
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);//��ÿ��� 
	if (hThreadSnap == INVALID_HANDLE_VALUE)return (FALSE);

	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32)){
		CloseHandle(hThreadSnap); // �رտ��� 
		return (FALSE);
	}
	do{//��ʾ�߳���Ϣ 
    	if (te32.th32OwnerProcessID == dwOwnerPID){
    		printf("\n\n         �߳�id     = %d", te32.th32ThreadID);
    		printf("\n         ���ȼ�     = %d", te32.tpBasePri);
    	}
	}
	while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return (TRUE);
}
BOOL GetProcessList(){//��ý����б� 
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//��ÿ��� 
	if (hProcessSnap == INVALID_HANDLE_VALUE) return (FALSE);

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)){//��ý�����Ϣ 
		CloseHandle(hProcessSnap); // �رտ��� 
	    return (FALSE);
	}
	do{//��ʾ 
		printf("\n\n=====================================================");
    	printf("\n������:  %s", pe32.szExeFile);
    	printf("\n-----------------------------------------------------");

    	dwPriorityClass = 0;
    	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
    	dwPriorityClass = GetPriorityClass(hProcess);// �������ȼ�
    	CloseHandle(hProcess);

    	printf("\n ����id   = %d", pe32.th32ProcessID);
    	printf("\n �߳����� = %d", pe32.cntThreads);
    	printf("\n ������id = %d", pe32.th32ParentProcessID);
    	printf("\n ���ȼ�   = %d", pe32.pcPriClassBase);
    	if (dwPriorityClass) printf("\n ���ȼ�   = %d", dwPriorityClass);

    	ListProcessModules(pe32.th32ProcessID);//��ý���ģ����Ϣ 
    	ListProcessThreads(pe32.th32ProcessID);//��ý����߳���Ϣ 
	}
	while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return (TRUE);
}

int main(int argc, char** argv){
	char* cpid;
	DWORD dpid;
	start:
	if(argc==1){
		printf("ʾ����x3-tool.exe [����] ([ֵ])\n");
		printf("һ����С�����ǿ���windows�����й���-x3tool  v3.0\n");
		printf("֧��ֱ������/�����е���\n");
		printf("�޷���ֵ�ķ���0��Ϊʧ��\n");
		printf("�ʼ�:admin@n103.top\n");
		printf("����:www.n103.top\n");
		printf("           by:  xbebhxx3\n\n");
		printf("x3-tool\n");
		printf("|- Ȩ�޲���                                     \n");
		printf("|    |- �жϹ���ԱȨ��  1��,0��             (ia)\n");
		printf("|    |- ��systemȨ�޴�                    (us)\n");
		printf("|    |- ��TrustedInstallerȨ�޴�          (ut)\n");
		printf("|- ���̲���                                     \n");
		printf("|   |- ��������                             (kp)\n");
		printf("|   |- �жϽ����Ƿ���� ,�����ؽ���id       (ip)\n");
		printf("|   |- ��ý���·��                         (gpl)\n");
		printf("|   |- �������                             (sp)\n");
		printf("|   |- ���ùؼ�����                         (cp)\n");
		printf("|   |- �г�����ģ��                         (lpm)\n");
		printf("|   |- �г������߳�                         (lpt)\n");
		printf("|   |- �г����н�����ϸ��Ϣ                 (lp)\n");
		printf("|- ��/�������                                  \n");
		printf("|      |- Url����                           (cu)\n");
		printf("|      |- Url����                           (du)\n");
		printf("|      |- ���׼���                          (xc)\n");
		printf("|- ����������                             (lkm)\n");
		printf("|- ִ��shell����                            (rs)\n");
		printf("|- ������λ��                             (mxy)\n");
		printf("|- ����                                     (cls)\n");
		printf("|- ��õ�ǰip                               (gi)\n");
		printf("|- ��õ�ǰ�û���                           (gu)\n");
		printf("|- ���ϵͳ�汾                             (gv)\n");
		printf("|- �������                                 (om)\n");
		printf("|- ���ش���                                 (hw)\n");
		printf("|- �桤ȫ��                                 (fc)\n");
		printf("|- ����                                     (h)\n");
		printf("|- �汾                                     (v)\n\n");
		printf("ʾ����x3-tool.exe sp 10010 1\n");
		input: 
		printf("\n>");
		cin.sync();
		cin>>gn;
	}
	else {
		strcpy(gn,argv[1]);
	}
	if(lstrcmp(gn,"ia")==0){
		printf("%d",IsProcessRunAsAdmin());
		if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"us")==0){
		if(argc==3)printf("%d",UseSystem(argv[2]));
		else {
			printf("[+] �ļ�·����"); 
			cin.sync();//������뻺���� 
			scanf("%[^\n]",&in);
			printf("%d",UseSystem(in));
			goto input;
		} 
	}
	else if(lstrcmp(gn,"ut")==0){
		if(argc==3)printf("%d",UseTrustedInstaller(argv[2]));
		else {
			printf("[+] �ļ�·����"); 
			cin.sync();//������뻺���� 
			scanf("%[^\n]",&in);
			printf("%d",UseTrustedInstaller(in));
			goto input;
		} 
	}
	else if(lstrcmp(gn,"kp")==0){
		if(argc==3)KillProcess(argv[2]);
		else {
			printf("[+] ��������"); 
			cin.sync();
			scanf("%[^\n]",&in);
			KillProcess(in);
			goto input;
		} 
	}
	else if(lstrcmp(gn,"ip")==0){
		if(argc==3)printf("%d",isProcess(argv[2]));
		else {
			printf("[+] ��������"); 
			cin.sync();
			scanf("%[^\n]",&in);
			printf("%d",isProcess(in));
			goto input;
		} 
	}
	else if(lstrcmp(gn,"gpl")==0){
		if(argc==3)printf("%s",GetProcesslocation(argv[2]).c_str());
		else {
			printf("[+] ��������"); 
			cin.sync();
			scanf("%[^\n]",&in);
			printf("%s",GetProcesslocation(in).c_str());
			goto input;
		} 
	}
	else if(lstrcmp(gn,"sp")==0){
		if(argc==4){
			char* cpid = argv[2];
			DWORD dpid = atoi(cpid);
			if(lstrcmp(argv[3],"1")==0)printf("%d",SuspendProcess(dpid,1));
			else printf("%d",SuspendProcess(dpid,0));
		}
		else {
			printf("[+] ����id��");
			cin.sync();
			scanf("%d",&dpid);
			printf("[+] 1����0�����"); 
			cin.sync();
			scanf("%[^\n]",&in);
			if(lstrcmp(in,"1")==0)printf("%d",SuspendProcess(dpid,1));
			else printf("%d",SuspendProcess(dpid,0));
			goto input;
		} 
	}
	else if(lstrcmp(gn,"cp")==0){
		if(argc==4){
			char* cpid = argv[2];
			DWORD dpid = atoi(cpid);
			if(lstrcmp(argv[3],"1")==0)printf("%d",CriticalProcess(dpid,1));
			else printf("%d",CriticalProcess(dpid,0));
		}
		else {
			printf("[+] ����id��");
			cin.sync();
			scanf("%d",&dpid);
			printf("[+] 1����0�����"); 
			cin.sync();
			scanf("%[^\n]",&in);
			if(lstrcmp(in,"1")==0)printf("%d",CriticalProcess(dpid,1));
			else printf("%d",CriticalProcess(dpid,0));
			goto input;
		} 
	}
	else if(lstrcmp(gn,"lpm")==0){
		if(argc==3){
			char* cpid = argv[2];
			DWORD dpid = atoi(cpid);
			ListProcessModules(dpid); 
		}
		else {
			printf("[+] ����id��");
			cin.sync();
			scanf("%d",&dpid);
			ListProcessModules(dpid); 
			goto input;
		}  
	}
	else if(lstrcmp(gn,"lpt")==0){
		if(argc==3){
			char* cpid = argv[2];
			DWORD dpid = atoi(cpid);
			ListProcessThreads(dpid); 
		}
		else {
			printf("[+] ����id��");
			cin.sync();
			scanf("%d",&dpid);
			ListProcessThreads(dpid); 
			goto input;
		} 
	}
	else if(lstrcmp(gn,"lp")==0){
		GetProcessList();
		goto input;
	}
	else if(lstrcmp(gn,"cu")==0){
		if(argc==3)printf("%s",CodeUrl(argv[2]).c_str());
		else {
			printf("[+] �����ַ�����"); 
			cin.sync();
			scanf("%[^\n]",&in);
			printf("%s",CodeUrl(in).c_str());
			goto input;
		} 
	}
else if(lstrcmp(gn,"du")==0){
		if(argc==3)printf("%s",DecodeUrl(argv[2]).c_str());
		else {
			printf("[+] �����ַ�����"); 
			cin.sync();
			scanf("%[^\n]",&in);
			printf("%s",DecodeUrl(in).c_str());
			goto input;
		} 
	}
	else if(lstrcmp(gn,"xc")==0){
		if(argc==3)printf("%s",x3code(argv[2]).c_str());
		else {
			printf("[+] �����ַ�����"); 
			cin.sync();
			scanf("%[^\n]",&in);
			printf("%s",x3code(in).c_str());
			goto input;
		} 
	}
	else if(lstrcmp(gn,"lkm")==0){
		if(argc==3){
			if(lstrcmp(argv[2],"1")==0)printf("%d",lockkm(1));
			else printf("%d",lockkm(0));
		}
		else {
			printf("[+] 1����0�����");  
			cin.sync();
			scanf("%[^\n]",&in);
			if(lstrcmp(in,"1")==0)printf("%d",lockkm(1));
			else printf("%d",lockkm(0));
			goto input;
		} 

	}
	else if(lstrcmp(gn,"rs")==0){
		if(argc==3) printf("%s",getCmdResult(argv[2]));
		else {
			printf("[+] ����exit�˳�\n");  
			while(1){
				printf("shell>");  
				cin.sync();
				scanf("%[^\n]",&in);
				if(lstrcmp(in,"exit")==0)goto input;
				printf("%s",getCmdResult(in)); 
			}
		}

	}
	else if(lstrcmp(gn,"mxy")==0){
			int x,y; 
			mouxy(x,y);
			printf("X:%d\nY:%d",x,y);
			if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"cls")==0){
	cls();
	if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"gi")==0){
		printf("%s",getIp().c_str());
		if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"gu")==0){
		printf("%s",GetUser().c_str());
		if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"gv")==0){
		printf("%s",GetSystemVersion().c_str());
		if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"om")==0){
		if(argc==4){
			char* cpid = argv[3];
			DWORD dpid = atoi(cpid);
			OutoutMiddle(argv[2],dpid);
		}
		else {
			printf("[+] �ַ�����");
			cin.sync();
			scanf("%[^\n]",&in);
			printf("[+] ������"); 
			cin.sync();
			scanf("%d",&dpid);
			OutoutMiddle(in,dpid);
			goto input;
		}  
	}
	else if(lstrcmp(gn,"hw")==0){
	HideWindow();
	if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"fc")==0){
	full_screen();
	if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"exit")==0){
		exit;
	}
	else if(lstrcmp(gn,"v")==0){
		printf("v3.0\n");
		if(argc!=2)goto input;
	}
	else if(lstrcmp(gn,"h")==0){
		goto start; 
	}
	else{
		printf("�������\n");
		goto input;
	}
    //GetProcessList();
}
