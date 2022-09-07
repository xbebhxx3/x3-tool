# x3-tool
一个超小体积的强大的windows命令行工具

# 依赖x3-f.h

# 功能
    x3-tool
    |- 权限操作
    |    |- 判断管理员权限  1有,0无              (ia)
    |    |- 以system权限打开                    (us)
    |    |- 以TrustedInstaller权限打开          (ut)
    |- 进程操作
    |   |- 结束进程                             (kp)
    |   |- 判断进程是否存在 ,并返回进程id        (ip)
    |   |- 获得进程路径                         (gpl)
    |   |- 挂起进程                             (sp)
    |   |- 设置关键进程                         (cp)
    |   |- 列出进程模块                         (lpm)
    |   |- 列出进程线程                         (lpt)
    |   |- 列出所有进程详细信息                  (lp)
    |- 编/解码操作
    |      |- Url编码                           (cu)
    |      |- Url解码                           (du)
    |      |- 简易加密                          (xc)
    |- 锁定鼠标键盘                             (lkm)
    |- 执行shell命令                            (rs)
    |- 获得鼠标位置                             (mxy)
    |- 清屏                                     (cls)
    |- 获得当前ip                               (gi)
    |- 获得当前用户名                           (gu)
    |- 获得系统版本                             (gv)
    |- 居中输出                                 (om)
    |- 隐藏窗口                                 (hw)
    |- 真·全屏                                 (fc)
    |- 帮助                                     (h)
    |- 版本                                     (v)
# 食用方法
1.直接运行并根据提示输入

2.命令行调用

3.在批处理文件中调用

## 命令行调用

在shell中根据提示顺序输入

### 示例：
x3-tool.exe sp 10010 1(挂起id为10010的进程)

x3-tool.exe sp 10010 0(取消挂起id为10010的进程)

x3-tool.exe ut cmd.exe(以TrustedInstaller权限打开cmd)

x3-tool gpl cmd.exe(获得进程名为cmd.exe的进程路径)

## 在批处理文件中调用

通过
    for /f %%i in ('命令') do set val=%%i 
获得命令返回值

### 示例：
    for /f %%i in ('"%~dp0x3-tool.exe" ip 123.exe') do set val=%%i 
    if %val% NEQ 0 "%~dp0x3-tool.exe" cp %val% 1
    
获得进程名为123.exe的进程id并设置关键进程

    @echo off
    %1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
    for /f %%i in ('"%~dp0x3-tool.exe" gu') do set val=%%i 
    if %val% NEQ SYSTEM "%~dp0x3-tool.exe" ut "%0"&&exit
    其他命令
    
以TrustedInstaller权限执行bat

# 编译环境
MinGW64（g++）

添加 -std=gnu++11 -lgdi32 -lwsock32
