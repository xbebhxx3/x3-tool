# x3-tool
一个强大的超小体积的windows命令行工具.
# 功能
x3-tool
|- 权限操作
|    |- 判断管理员权限  1有,0无              (ia).
|    |- 以system权限打开                    (us).
|    |- 以TrustedInstaller权限打开          (ut).
|- 进程操作.
|   |- 结束进程                             (kp).
|   |- 判断进程是否存在 ,并返回进程id         (ip).
|   |- 获得进程路径                         (gpl).
|   |- 挂起进程                             (sp).
|   |- 设置关键进程                         (cp).
|   |- 列出进程模块                         (lpm).
|   |- 列出进程线程                         (lpt).
|   |- 列出所有进程详细信息                  (lp).
|- 编/解码操作.
|      |- Url编码                           (cu).
|      |- Url解码                           (du).
|      |- 简易加密                          (xc).
|- 锁定鼠标键盘                             (lkm).
|- 执行shell命令                            (rs).
|- 获得鼠标位置                             (mxy).
|- 清屏                                     (cls).
|- 获得当前ip                               (gi).
|- 获得当前用户名                           (gu).
|- 获得系统版本                             (gv).
|- 居中输出                                 (om).
|- 隐藏窗口                                 (hw).
|- 真·全屏                                 (fc).
# 编译环境
MinGW64（g++）.
添加 -std=gnu++11 -lgdi32 -lwsock32.
