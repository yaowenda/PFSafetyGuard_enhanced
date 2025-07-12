#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QThread>
#include <windows.h>
#include <psapi.h>
#include <QCloseEvent>
#include <WinSock2.h>  // 必须在 Windows.h 之前包含
#include <WS2tcpip.h>  // 包含 AF_INET6 的定义
#include <Windows.h>

// 如果使用 WinSock2，需要链接 Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

using namespace std;
#define MESSAGEBOXA              1  // 弹窗
#define MESSAGEBOXW              2  // 弹窗
#define WRITEFILE                3  // 写文件
#define READFILE                 4  // 读文件
#define CREATEFILEA              5  // 打开或创建文件
#define CREATEFILEW              6  // 打开或创建文件
#define DELETEFILEA              7  // 删除文件
#define DELETEFILEW              8  // 删除文件
#define GETFILEATTRIBUTESW       9  // 获取文件属性
#define GETFILESIZE             10  // 获取文件大小
#define MOVEFILEW               11  // 移动或重命名文件
#define MOVEFILEEXW             12  // 移动文件（支持更多选项）
#define SEND                    13  // 发送数据
#define SENDTO                  14  // 发送数据到指定地址
#define WSASEND                 15  // 发送数据
#define RECV                    16  // 接收数据
#define RECVFROM                17  // 接收远程数据
#define WSARECV                 18  // 接收数据
#define CONNECT                 19  // 建立连接
#define WSACONNECT              20  // 建立连接
#define GETHOSTBYNAME           21  // 域名解析
#define GETADDRINFO             22  // 域名/IP解析
#define SOCKET_CREATE           23  // 创建套接字
#define SOCKET_CLOSE            24  // 关闭套接字
#define CREATEPROCESSA          25  // 创建进程（ANSI版本）
#define CREATEPROCESSW          26  // 创建进程（Unicode版本）
#define SHELLEXECUTEW           27  // 执行shell命令（Unicode版本）
#define CREATETHREAD            28  // 创建线程
#define EXITTHREAD              29  // 终止线程
#define LOADLIBRARYA            30  // 加载动态库（ANSI版本）
#define LOADLIBRARYW            31  // 加载动态库（Unicode版本）
#define LOADLIBRARYEXA          32  // 加载动态库（扩展参数，Unicode版本）
#define GETPROCADDRESS          33  // 获取函数地址
#define VIRTUALALLOCEX          34  // 在远程进程中分配内存
#define WRITEPROCESSMEMORY      35  // 向远程进程写入内存
#define CREATEREMOTETHREAD      36  // 在远程进程中创建线程
#define CREATEWINDOWEXA         37  // 创建窗口（扩展样式，ANSI版本）
#define CREATEWINDOWEXW         38  // 创建窗口（扩展样式，Unicode版本）
#define REGISTERCLASSA          39  // 注册窗口类（ANSI版本）
#define REGISTERCLASSW          40  // 注册窗口类（Unicode版本）
#define SETWINDOWLONGA          41  // 设置窗口属性（ANSI版本）
#define SETWINDOWLONGW          42  // 设置窗口属性（Unicode版本）
#define SHOWWINDOW              43  // 显示窗口
#define DESTROYWINDOW           44  // 销毁窗口
#define GETASYNCKEYSTATE        45  // 检查某个键被按下还是释放
#define GETKEYSTATE             46  // 获取指定虚拟键的状态
#define REGISTERHOTKEY          47  // 注册一个系统范围的热键（全局快捷键）
#define SETWINDOWSHOOKEXA       48  // 该函数用于安装一个钩子，它可以拦截并处理各种类型的输入事件或其他消息。
#define GETCURSORPOS            49  // 获取鼠标光标坐标
#define SETCURSORPOS            50  // 将光标移动到指定位置
#define VIRTUALFREE             51  // 用于释放或取消保留调拨的虚拟内存
#define NTQUERYSYSTEMINFORMATION 52 // 获取系统级别的信息（如进程列表、线程列表、句柄表等）
#define NTREADVIRTUALMEMORY     53  // 从指定进程的虚拟地址空间中读取内存数据

struct info {
    int type, argNum;
    SYSTEMTIME st;
    char argName[100][2048];
    char argValue[100][4096];
};

class myThread :public QThread {
	Q_OBJECT
private:
	bool running;
	char filePath[256], fileName[128];
	unordered_set<int> heapSet;
	unordered_set<string> folderSet;
    DWORD exitCode;
    HANDLE hProcess;
protected:
	void run();
public:
	void init(char * path);
	void getFileName(char *filePath, char *fileName);
	void stopThread();
	int GetProcessPriority(HANDLE hProcess);
	void checkFunc();
	void createFileCheck();
	void getLastFolder(char* filePath, string & folder);
signals:
	void newValue(QString str);
	void newInfo();
	void newProcessName(QString str);
	void newProcessID(QString str);
	void newProcessPriority(QString str);
	void newProcessModules(QString str);
	void newInfo(QString str, int status);
};

class MainWindow : public QMainWindow
{
    Q_OBJECT
private:
	myThread threadA;
protected:
	void closeEvent(QCloseEvent *event);
private slots:
	void on_openFileButton_pressed();
	void on_tempButton_pressed();
	void on_clsButton_pressed();
	void on_ThreadA_newValue(QString str);
	void on_ThreadA_newInfo();
	void on_ThreadA_newProcessName(QString str);
	void on_ThreadA_newProcessID(QString str);
	void on_ThreadA_newProcessPriority(QString str);
	void on_ThreadA_newProcessModules(QString str);
	void on_ThreadA_newInfo(QString str, int status);
public:
    MainWindow(QWidget *parent = nullptr);
	void initUI();
    ~MainWindow();
private:
    Ui::MainWindow *ui;
};


#endif // MAINWINDOW_H
