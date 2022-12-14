# x3-tool
一个超小体积的强大的windows命令行工具

# 依赖x3-f.h

# 功能
    x3-tool
    |- 权限操作                                     
    |    |- 判断管理员权限  1有 0无             (ia)
    |    |- 以管理员权限打开                    (ua)
    |    |- 以system权限打开                    (us)
    |    |- 以TrustedInstaller权限打开          (ut)
    |    |- 以administrator权限重启工具         (ra)
    |    |- 以TrustedInstaller权限重启工具      (rt)
    |- 进程操作                                     
    |   |- 结束进程                             (kp)
    |   |- 判断进程是否存在 ,并返回进程id       (ip)
    |   |- 获得进程路径                         (gpl)
    |   |- 挂起进程                             (sp)
    |   |- 设置关键进程                         (cp)
    |   |- 停止服务                             (cs)
    |   |- 启动服务                             (ss)
    |   |- 列出所有服务                         (ls)
    |   |- 列出进程模块                         (lpm)
    |   |- 列出进程线程                         (lpt)
    |   |- 列出所有进程详细信息                 (lp)
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
    |- 真·全屏                                 (fc)
    |- 随机数                                   (rn)
# 食用方法
1.直接运行并根据提示输入

2.命令行调用

3.在批处理文件中调用

## 命令行调用

在shell中根据提示顺序输入

### 示例：
- `x3-tool.exe ip cmd.exe`(获得进程名为cmd.exe的进程id)

- `x3-tool.exe sp 1000 1`(挂起id为1000的进程)

- `x3-tool.exe sp 1000 0`(取消挂起id为1000的进程)

- `x3-tool.exe ut cmd.exe`(以TrustedInstaller权限打开cmd)

- x3-tool gpl 1000(获得进程名为cmd.exe的进程路径)

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

# 编译
编译环境：MinGW64（g++）

添加 `-Os -lgdi32 -lwsock32 -Wl,-gc-sections -fno-exceptions -fno-rtti`(除了`-lgdi32 -lwsock32`必须添加之外其他的都是为了减小体积)

下载 https://github.com/xbebhxx3/x3-f.h 并添加

