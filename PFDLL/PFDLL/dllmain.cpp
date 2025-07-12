#include "pch.h"
#include "framework.h"
#include "detours.h"
#include "stdio.h"
#include "stdarg.h"
#include "windows.h"
#include <iostream>
#include <string>
#include <stdlib.h>
#include <unordered_map>
#include <WinSock2.h>
#pragma comment(lib, "detours.lib")
#pragma comment (lib, "ws2_32.lib")  //加载 ws2_32.dll
#pragma comment(lib, "ntdll.lib")
#include <shlobj.h>
#include <winuser.h>
#include <winternl.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <Windows.h>
#include <WinDef.h>
using namespace std;
SYSTEMTIME st;
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

info sendInfo;
HANDLE hSemaphore = NULL;
HANDLE hMapFile = NULL;
LPVOID lpBase = NULL;

//初始化共享内存和信号量
void InitHook() {
	hSemaphore = OpenSemaphore(EVENT_ALL_ACCESS, FALSE, L"mySemaphore");
	hMapFile = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, L"ShareMemory");
	lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(info));

}

// 定义需要hook的函数
static int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;
// 定义需要替换的新的函数
extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
	MessageBoxW(NULL, L"HOOKED", L"HOOKED", MB_OK);

	// 返回原始接口
	return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
}

///*
//* ------------------------------------------------------------------------------------------------------
//  ----------------------------------------------- 王博 -------------------------------------------------
//  ------------------------------------------------------------------------------------------------------
//*/

// 保存原始函数地址
static BOOL(WINAPI* OldReadFile)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	) = ReadFile;

// 读文件
extern "C" __declspec(dllexport) BOOL WINAPI NewReadFile(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	// 设置信息类型
	sendInfo.type = READFILE;
	sendInfo.argNum = 5;
	GetLocalTime(&(sendInfo.st));

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "hFile");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpBuffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "nNumberOfBytesToRead");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpNumberOfBytesRead");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpOverlapped");

	// 参数值（转十六进制指针/数值）
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (DWORD_PTR)hFile);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", (DWORD_PTR)lpBuffer);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", nNumberOfBytesToRead);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpNumberOfBytesRead);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", (DWORD_PTR)lpOverlapped);

	// 写入共享内存并释放信号量
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	sendInfo.argNum = 0;

	// 调用原始 ReadFile
	return OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}



//打开文件
static HANDLE(WINAPI* OldCreateFileA)(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	) = CreateFileA;

extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateFileA(
	LPCSTR                lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	HANDLE hFile = OldCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (GetFileType(hFile) == FILE_TYPE_DISK) {
		sendInfo.argNum = 7;

		// 参数名
		sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");
		sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwDesiredAccess");
		sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwShareMode");
		sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpSecurityAttributes");
		sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "dwCreationDisposition");
		sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "dwFlagsAndAttributes");
		sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "hTemplateFile");

		// 参数值（ANSI字符串直接赋值）
		if (lpFileName) {
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), lpFileName, _TRUNCATE);
		}
		else {
			strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
		}

		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", dwDesiredAccess);
		sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", dwShareMode);
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", (DWORD_PTR)lpSecurityAttributes);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", dwCreationDisposition);
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", dwFlagsAndAttributes);
		sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "%08X", (DWORD_PTR)hTemplateFile);

		sendInfo.type = CREATEFILEA;
		GetLocalTime(&(sendInfo.st));

		memcpy(lpBase, &sendInfo, sizeof(sendInfo));
		ReleaseSemaphore(hSemaphore, 1, NULL);
		sendInfo.argNum = 0;
	}

	return hFile;
}

// 写文件
static BOOL(WINAPI* OldWriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	) = WriteFile;

extern "C" __declspec(dllexport)BOOL WINAPI NewWriteFile(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
)
{
	if (GetFileType(hFile) == FILE_TYPE_DISK) {
		sendInfo.argNum = 5;
		// 参数名
		sprintf(sendInfo.argName[0], "hFile");
		sprintf(sendInfo.argName[1], "lpBuffer");
		sprintf(sendInfo.argName[2], "nNumberOfBytesToWrite");
		sprintf(sendInfo.argName[3], "lpNumberOfBytesWritten");
		sprintf(sendInfo.argName[4], "lpOverlapped");
		// 参数值
		sprintf(sendInfo.argValue[0], "%08X", hFile);
		sprintf(sendInfo.argValue[1], "%08X", lpBuffer);
		sprintf(sendInfo.argValue[2], "%08X", nNumberOfBytesToWrite);
		sprintf(sendInfo.argValue[3], "%08X", lpNumberOfBytesWritten);
		sprintf(sendInfo.argValue[4], "%08X", lpOverlapped);

		sendInfo.type = WRITEFILE;
		GetLocalTime(&(sendInfo.st));
		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);
	}
	return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

//文件属性
static DWORD(WINAPI* OldGetFileAttributesW)(LPCWSTR lpFileName) = GetFileAttributesW;

extern "C" __declspec(dllexport) DWORD WINAPI NewGetFileAttributesW(LPCWSTR lpFileName)
{
	DWORD result = OldGetFileAttributesW(lpFileName);

	sendInfo.type = GETFILEATTRIBUTESW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpFileName");

	// 参数值（宽字符转换为 ANSI）
	char temp[256] = { 0 };
	if (lpFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//简单移动/重命名文件
static BOOL(WINAPI* OldMoveFileW)(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
	) = MoveFileW;

extern "C" __declspec(dllexport) BOOL WINAPI NewMoveFileW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName
)
{
	char temp[100] = { 0 };

	sendInfo.type = MOVEFILEW;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpExistingFileName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpNewFileName");

	// 参数值（宽字符转多字节）
	if (lpExistingFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpExistingFileName, -1, temp, sizeof(temp) - 1, NULL, NULL);
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);
	}

	memset(temp, 0, sizeof(temp));
	if (lpNewFileName) {
		WideCharToMultiByte(CP_ACP, 0, lpNewFileName, sizeof(lpNewFileName), temp, sizeof(temp), NULL, NULL);
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), temp, _TRUNCATE);
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}

	// 写入共享内存并释放信号量
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldMoveFileW(lpExistingFileName, lpNewFileName);
}
//send(通过一个 已建立连接的套接字（SOCK_STREAM，即 TCP） 发送数据。)
static int (WINAPI* OldSend)(SOCKET s, const char* buf, int len, int flags) = send;

extern "C" __declspec(dllexport) int WINAPI NewSend(SOCKET s, const char* buf, int len, int flags) {
	sendInfo.argNum = 4;
	sendInfo.type = SEND;
	GetLocalTime(&(sendInfo.st));

	strcpy_s(sendInfo.argName[0], "s");
	strcpy_s(sendInfo.argName[1], "buf");
	strcpy_s(sendInfo.argName[2], "len");
	strcpy_s(sendInfo.argName[3], "flags");

	sprintf_s(sendInfo.argValue[0], "%08X", s);
	if (buf && len > 0) {
		strncpy_s(sendInfo.argValue[1], buf, min(len, 255));
		sendInfo.argValue[1][min(len, 255)] = '\0';
	}
	else {
		strcpy_s(sendInfo.argValue[1], "(null)");
	}
	sprintf_s(sendInfo.argValue[2], "%d", len);
	sprintf_s(sendInfo.argValue[3], "%08X", flags);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSend(s, buf, len, flags);
}

//sendto(用于通过一个套接字（可以是 UDP 或未连接的 TCP）向指定地址发送数据，适用于无连接协议（如 UDP）。
static int (WINAPI* OldSendTo)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) = sendto;

extern "C" __declspec(dllexport) int WINAPI NewSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
	sendInfo.argNum = 6;
	sendInfo.type = SENDTO;
	GetLocalTime(&(sendInfo.st));

	strcpy_s(sendInfo.argName[0], "s");
	strcpy_s(sendInfo.argName[1], "buf");
	strcpy_s(sendInfo.argName[2], "len");
	strcpy_s(sendInfo.argName[3], "flags");
	strcpy_s(sendInfo.argName[4], "to");
	strcpy_s(sendInfo.argName[5], "tolen");

	sprintf_s(sendInfo.argValue[0], "%08X", s);
	if (buf && len > 0) {
		strncpy_s(sendInfo.argValue[1], buf, min(len, 255));
		sendInfo.argValue[1][min(len, 255)] = '\0';
	}
	else {
		strcpy_s(sendInfo.argValue[1], "(null)");
	}
	sprintf_s(sendInfo.argValue[2], "%d", len);
	sprintf_s(sendInfo.argValue[3], "%08X", flags);
	sprintf_s(sendInfo.argValue[4], "%08X", to ? to : 0);
	sprintf_s(sendInfo.argValue[5], "%d", tolen);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSendTo(s, buf, len, flags, to, tolen);
}

//接收数据recv
static int (WINAPI* OldRecv)(SOCKET s, char* buf, int len, int flags) = recv;

extern "C" __declspec(dllexport) int WINAPI NewRecv(SOCKET s, char* buf, int len, int flags)
{
	int result = OldRecv(s, buf, len, flags);  // ✅ 先真正接收数据

	if (result > 0) {
		sendInfo.type = RECV;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 4;

		// 参数名
		strcpy_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
		strcpy_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
		strcpy_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
		strcpy_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");

		// 参数值
		sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);

		// 拷贝前64字节数据用于预览
		int copyLen = min(result, 64);
		char tmpBuf[65] = { 0 };
		memcpy(tmpBuf, buf, copyLen);
		tmpBuf[copyLen] = '\0';

		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), tmpBuf, _TRUNCATE);
		sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", result);
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", flags);

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(sendInfo));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
	}

	return result;
}

//recvfrom
static int (WINAPI* OldRecvFrom)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) = recvfrom;

extern "C" __declspec(dllexport) int WINAPI NewRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
	sendInfo.type = RECVFROM;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 6;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "Socket");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Buffer");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Length");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "Flags");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "From");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "FromLen");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", (unsigned int)s);

	if (buf && len > 0) {
		int copyLen = min(len, 64);
		char tmpBuf[65] = { 0 };
		memcpy(tmpBuf, buf, copyLen);
		tmpBuf[copyLen] = '\0';
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), tmpBuf, _TRUNCATE);
	}
	else {
		strcpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)");
	}

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", len);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", flags);

	// 打印 from 地址（IPv4 示例）
	if (from && fromlen && *fromlen >= sizeof(sockaddr_in)) {
		sockaddr_in* addr_in = (sockaddr_in*)from;
		char ip[16] = { 0 };
		sprintf_s(ip, sizeof(ip), "%d.%d.%d.%d",
			addr_in->sin_addr.S_un.S_un_b.s_b1,
			addr_in->sin_addr.S_un.S_un_b.s_b2,
			addr_in->sin_addr.S_un.S_un_b.s_b3,
			addr_in->sin_addr.S_un.S_un_b.s_b4);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%s:%d", ip, ntohs(addr_in->sin_port));
	}
	else {
		strcpy_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "(null)");
	}

	if (fromlen) {
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%d", *fromlen);
	}
	else {
		strcpy_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "(null)");
	}

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldRecvFrom(s, buf, len, flags, from, fromlen);
}

//connect(用于通过一个未连接的套接字（SOCK_STREAM，即 TCP）连接到指定地址，通常用于建立 TCP 连接。
static int (WINAPI* OldConnect)(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
	) = connect;

extern "C" __declspec(dllexport) int WINAPI NewConnect(
	SOCKET s,
	const struct sockaddr* name,
	int namelen
)

{
	sendInfo.argNum = 3;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);
	if (name && namelen >= sizeof(sockaddr_in)) {
		const sockaddr_in* addr = (const sockaddr_in*)name;
		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%s:%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", namelen);

	sendInfo.type = CONNECT;
	GetLocalTime(&sendInfo.st);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldConnect(s, name, namelen);
}

static int (WINAPI* OldWSAConnect)(
	SOCKET s,
	const struct sockaddr* name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS
	) = WSAConnect;

extern "C" __declspec(dllexport) int WINAPI NewWSAConnect(
	SOCKET s,
	const struct sockaddr* name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS
)

{
	sendInfo.argNum = 7;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "name");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "namelen");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "lpCallerData");
	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "lpCalleeData");
	sprintf_s(sendInfo.argName[5], sizeof(sendInfo.argName[5]), "lpSQOS");
	sprintf_s(sendInfo.argName[6], sizeof(sendInfo.argName[6]), "lpGQOS");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);
	if (name && namelen >= sizeof(sockaddr_in)) {
		const sockaddr_in* addr = (const sockaddr_in*)name;
		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%s:%d",
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	}
	else {
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);
	}
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%d", namelen);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%08X", lpCallerData);
	sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%08X", lpCalleeData);
	sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", lpSQOS);
	sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "%08X", lpGQOS);

	sendInfo.type = WSACONNECT;
	GetLocalTime(&sendInfo.st);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

//IPv4/IPv6 统一解析接口
static int (WINAPI* Old_getaddrinfo)(
	PCSTR pNodeName,
	PCSTR pServiceName,
	const ADDRINFOA* pHints,
	PADDRINFOA* ppResult
	) = getaddrinfo;

extern "C" __declspec(dllexport)
int WINAPI New_getaddrinfo(
	PCSTR pNodeName,
	PCSTR pServiceName,
	const ADDRINFOA * pHints,
	PADDRINFOA * ppResult
)
{
	sendInfo.type = GETADDRINFO;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "pNodeName");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "pServiceName");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "pHints");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "ppResult");

	if (pNodeName)
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), pNodeName, _TRUNCATE);
	else
		strncpy_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "(null)", _TRUNCATE);

	if (pServiceName)
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), pServiceName, _TRUNCATE);
	else
		strncpy_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "(null)", _TRUNCATE);

	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", pHints);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p", ppResult);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return Old_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

// 创建socket
static SOCKET(WINAPI* OldSocket)(
	int af,
	int type,
	int protocol
	) = socket;

extern "C" __declspec(dllexport) SOCKET WINAPI NewSocket(
	int af,
	int type,
	int protocol
) {
	sendInfo.argNum = 3;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "af");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "type");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "protocol");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", af);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%08X", type);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%08X", protocol);

	sendInfo.type = SOCKET_CREATE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldSocket(af, type, protocol);
}
// 关闭socket
static int (WINAPI* OldCloseSocket)(SOCKET s) = closesocket;

// Hook 函数实现
extern "C" __declspec(dllexport) int WINAPI NewCloseSocket(SOCKET s) {
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "s");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%08X", s);

	sendInfo.type = SOCKET_CLOSE;
	GetLocalTime(&(sendInfo.st));

	memcpy(lpBase, &sendInfo, sizeof(info));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldCloseSocket(s);
}




///*
//* ------------------------------------------------------------------------------------------------------
//  ----------------------------------------------- 沈丽彤 -------------------------------------------------
//  ------------------------------------------------------------------------------------------------------
//*/

// 原始函数
	static BOOL(WINAPI * OldCreateProcessW)(
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		) = CreateProcessW;

	// 定义Hook后函数
	extern "C" __declspec(dllexport) BOOL WINAPI NewCreateProcessW(
		_In_opt_ LPCWSTR lpApplicationName,
		_Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		char temp[256] = { 0 };

		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = CREATEPROCESSW;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 10;

		// 参数名
		const char* paramNames[] = {
			"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
			"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
			"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
			"lpProcessInformation"
		};
		for (int i = 0; i < 10; i++) {
			strcpy(sendInfo.argName[i], paramNames[i]);
		}

		// 参数值处理
		//  lpApplicationName
		if (lpApplicationName) {
			WideCharToMultiByte(CP_ACP, 0, lpApplicationName, -1, temp, sizeof(temp), NULL, NULL);
			strcpy(sendInfo.argValue[0], temp);
		}
		else {
			strcpy(sendInfo.argValue[0], "NULL");
		}

		// lpCommandLine 
		if (lpCommandLine) {
			WideCharToMultiByte(CP_ACP, 0, lpCommandLine, -1, temp, sizeof(temp), NULL, NULL);
			strcpy(sendInfo.argValue[1], temp);
		}
		else {
			strcpy(sendInfo.argValue[1], "NULL");
		}

		sprintf(sendInfo.argValue[2], "%p", lpProcessAttributes);
		sprintf(sendInfo.argValue[3], "%p", lpThreadAttributes);
		sprintf(sendInfo.argValue[4], "%d", bInheritHandles);
		sprintf(sendInfo.argValue[5], "%08X", dwCreationFlags);
		sprintf(sendInfo.argValue[6], "%p", lpEnvironment);
		if (lpCurrentDirectory) {
			WideCharToMultiByte(CP_ACP, 0, lpCurrentDirectory, -1, temp, sizeof(temp), NULL, NULL);
			strcpy(sendInfo.argValue[7], temp);
		}
		else {
			strcpy(sendInfo.argValue[7], "NULL");
		}

		sprintf(sendInfo.argValue[8], "%p", lpStartupInfo);
		sprintf(sendInfo.argValue[9], "%p", lpProcessInformation);

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		// 调用原始函数
		return OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags,
			lpEnvironment, lpCurrentDirectory, lpStartupInfo,
			lpProcessInformation);
	}

	// 原始函数
	static BOOL(WINAPI* OldCreateProcessA)(
		_In_opt_ LPCSTR lpApplicationName,
		_Inout_opt_ LPSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOA lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation
		) = CreateProcessA;

	// Hook后函数
	extern "C" __declspec(dllexport) BOOL WINAPI NewCreateProcessA(
		_In_opt_ LPCSTR lpApplicationName,
		_Inout_opt_ LPSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles,
		_In_ DWORD dwCreationFlags,
		_In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCSTR lpCurrentDirectory,
		_In_ LPSTARTUPINFOA lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		// 记录调用信息
		ZeroMemory(&sendInfo, sizeof(sendInfo));
		sendInfo.type = CREATEPROCESSA;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 10;

		// 参数名
		const char* paramNames[] = {
			"lpApplicationName", "lpCommandLine", "lpProcessAttributes",
			"lpThreadAttributes", "bInheritHandles", "dwCreationFlags",
			"lpEnvironment", "lpCurrentDirectory", "lpStartupInfo",
			"lpProcessInformation"
		};

		for (int i = 0; i < 10; i++) {
			strcpy_s(sendInfo.argName[i], sizeof(sendInfo.argName[i]), paramNames[i]);
		}

		// 参数值处理
		sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%.255s",
			lpApplicationName ? lpApplicationName : "NULL");

		sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%.255s",
			lpCommandLine ? lpCommandLine : "NULL");

		sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", lpProcessAttributes);
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p", lpThreadAttributes);
		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%d", bInheritHandles);
		sprintf_s(sendInfo.argValue[5], sizeof(sendInfo.argValue[5]), "%08X", dwCreationFlags);

		if (lpEnvironment) {
			char hexBuf[512] = { 0 };
			size_t envLen = min(128, (int)strlen((char*)lpEnvironment));
			for (size_t i = 0; i < envLen; i++) {
				char temp[10];
				sprintf_s(temp, sizeof(temp), "%02X ", ((BYTE*)lpEnvironment)[i]);
				strcat_s(hexBuf, sizeof(hexBuf), temp);
			}
			sprintf_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]),
				"EnvData[%p]: %s", lpEnvironment, hexBuf);
		}
		else {
			strcpy_s(sendInfo.argValue[6], sizeof(sendInfo.argValue[6]), "NULL");
		}

		sprintf_s(sendInfo.argValue[7], sizeof(sendInfo.argValue[7]), "%.260s",
			lpCurrentDirectory ? lpCurrentDirectory : "NULL");

		if (lpStartupInfo) {
			sprintf_s(sendInfo.argValue[8], sizeof(sendInfo.argValue[8]),
				"StartupInfo{Title=%.50s, Desktop=%.50s, Flags=%X}",
				lpStartupInfo->lpTitle ? lpStartupInfo->lpTitle : "NULL",
				lpStartupInfo->lpDesktop ? lpStartupInfo->lpDesktop : "NULL",
				lpStartupInfo->dwFlags);
		}
		else {
			strcpy_s(sendInfo.argValue[8], sizeof(sendInfo.argValue[8]), "NULL");
		}

		if (lpProcessInformation) {
			sprintf_s(sendInfo.argValue[9], sizeof(sendInfo.argValue[9]),
				"ProcessInfo{ hProcess=%p, hThread=%p }",
				lpProcessInformation->hProcess, lpProcessInformation->hThread);
		}
		else {
			strcpy_s(sendInfo.argValue[9], sizeof(sendInfo.argValue[9]), "NULL");
		}

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(sendInfo));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		sendInfo.argNum = 0;  // 清除参数数量

		return OldCreateProcessA(
			lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags,
			lpEnvironment, lpCurrentDirectory, lpStartupInfo,
			lpProcessInformation);
	}


	// 原始函数
	static HANDLE(WINAPI* OldCreateThread)(
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ SIZE_T dwStackSize,
		_In_ LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_ LPVOID lpParameter,
		_In_ DWORD dwCreationFlags,
		_Out_opt_ LPDWORD lpThreadId
		) = CreateThread;

	// Hook后函数
	extern "C" __declspec(dllexport) HANDLE WINAPI NewCreateThread(
		_In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ SIZE_T dwStackSize,
		_In_ LPTHREAD_START_ROUTINE lpStartAddress,
		_In_opt_ LPVOID lpParameter,
		_In_ DWORD dwCreationFlags,
		_Out_opt_ LPDWORD lpThreadId)
	{
		// 记录调用信息
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = CREATETHREAD;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 6;

		// 参数名
		const char* paramNames[] = {
			"lpThreadAttributes", "dwStackSize", "lpStartAddress",
			"lpParameter", "dwCreationFlags", "lpThreadId"
		};
		for (int i = 0; i < 6; i++) {
			strcpy(sendInfo.argName[i], paramNames[i]);
		}
		sprintf(sendInfo.argValue[0], "%p", lpThreadAttributes);
		sprintf(sendInfo.argValue[1], "%zu", dwStackSize);
		sprintf(sendInfo.argValue[2], "%p", lpStartAddress);
		sprintf(sendInfo.argValue[3], "%p", lpParameter);
		char flagsStr[100] = { 0 };
		if (dwCreationFlags & CREATE_SUSPENDED) strcat(flagsStr, "SUSPENDED|");
		if (dwCreationFlags & STACK_SIZE_PARAM_IS_A_RESERVATION) strcat(flagsStr, "STACK_RESERVE|");
		if (strlen(flagsStr) > 0) {
			flagsStr[strlen(flagsStr) - 1] == '\0';
		}

		sprintf(sendInfo.argValue[4], "%08X (%s)", dwCreationFlags, strlen(flagsStr) ? flagsStr : "DEFAULT");
		sprintf(sendInfo.argValue[5], "%p", lpThreadId);

		memcpy(lpBase, &sendInfo, sizeof(info));
		ReleaseSemaphore(hSemaphore, 1, NULL);

		return OldCreateThread(
			lpThreadAttributes, dwStackSize, lpStartAddress,
			lpParameter, dwCreationFlags, lpThreadId);
	}

	// 原始函数
	static VOID(WINAPI* OldExitThread)(_In_ DWORD dwExitCode) = ExitThread;

	// Hook后函数
	extern "C" __declspec(dllexport) VOID WINAPI NewExitThread(_In_ DWORD dwExitCode)
	{
		// 记录调用信息
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = EXITTHREAD;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 1;
		strcpy(sendInfo.argName[0], "dwExitCode");
		sprintf(sendInfo.argValue[0], "%08X", dwExitCode);

		

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}
		Sleep(50); // 50ms 已足够
		// 调用原始函数
		OldExitThread(dwExitCode);

	}

	// 原始函数指针
	static HMODULE(WINAPI* OldLoadLibraryExA)(
		_In_ LPCSTR lpLibFileName,
		_Reserved_ HANDLE hFile,
		_In_ DWORD dwFlags
		) = LoadLibraryExA;

	// Hook后的函数
	extern "C" __declspec(dllexport) HMODULE WINAPI NewLoadLibraryExA(
		_In_ LPCSTR lpLibFileName,
		_Reserved_ HANDLE hFile,
		_In_ DWORD dwFlags)
	{
		char flagsStr[100] = { 0 };

		// 清空结构体
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = LOADLIBRARYEXA;  // 注意：你需要在枚举类型中定义 LOADLIBRARYEXA
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 3;

		// 参数名
		strcpy(sendInfo.argName[0], "lpLibFileName");
		strcpy(sendInfo.argName[1], "dwFlags");
		strcpy(sendInfo.argName[2], "hFile");

		// 参数值
		if (lpLibFileName) {
			strncpy(sendInfo.argValue[0], lpLibFileName, sizeof(sendInfo.argValue[0]) - 1);
		}
		else {
			strcpy(sendInfo.argValue[0], "NULL");
		}

		// 标志位解析
		if (dwFlags & DONT_RESOLVE_DLL_REFERENCES) strcat(flagsStr, "DONT_RESOLVE|");
		if (dwFlags & LOAD_LIBRARY_AS_DATAFILE) strcat(flagsStr, "AS_DATAFILE|");
		if (dwFlags & LOAD_WITH_ALTERED_SEARCH_PATH) strcat(flagsStr, "ALTERED_SEARCH_PATH|");

		if (strlen(flagsStr) > 0) {
			flagsStr[strlen(flagsStr) - 1] = '\0'; // 去掉末尾 |
		}
		else {
			strcpy(flagsStr, "DEFAULT");
		}

		snprintf(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "0x%08X (%s)", dwFlags, flagsStr);
		snprintf(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", hFile);

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		// 调用原始API
		return OldLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	}

	// 原始函数指针声明
	static FARPROC(WINAPI* OldGetProcAddress)(
		_In_ HMODULE hModule,
		_In_ LPCSTR lpProcName
		) = GetProcAddress;

	// Hook后函数
	extern "C" __declspec(dllexport) FARPROC WINAPI NewGetProcAddress(
		_In_ HMODULE hModule,
		_In_ LPCSTR lpProcName)
	{
		char modName[MAX_PATH] = { 0 };

		// 记录调用信息
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = GETPROCADDRESS;
		GetLocalTime(&(sendInfo.st));
		sendInfo.argNum = 2;

		// 参数名
		strcpy(sendInfo.argName[0], "hModule");
		strcpy(sendInfo.argName[1], "lpProcName");


		// 参数值处理
		sprintf(sendInfo.argValue[0], "%p", hModule);

		// 获取模块文件名
		if (hModule && GetModuleFileNameA(hModule, modName, MAX_PATH)) {
			char* fileName = strrchr(modName, '\\');
			fileName = fileName ? fileName + 1 : modName;
			sprintf(sendInfo.argValue[0], "%p (%s)", hModule, fileName);
		}

		// 处理函数名（可能是序号）
		if (IS_INTRESOURCE(lpProcName)) {
			sprintf(sendInfo.argValue[1], "#%d", (DWORD)lpProcName);
		}
		else {
			sprintf(sendInfo.argValue[1], "%s", lpProcName ? lpProcName : "NULL");
		}

		// 写入共享内存
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		return OldGetProcAddress(hModule, lpProcName);
	}

	// 原始函数
	static LPVOID(WINAPI* OldVirtualAllocEx)(
		_In_ HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD flAllocationType,
		_In_ DWORD flProtect
		) = VirtualAllocEx;

	// 保护属性解析函数
	const char* GetMemoryProtectionString(DWORD protect) {
		static char buffer[128];
		ZeroMemory(buffer, sizeof(buffer));

		// 基础保护属性
		switch (protect & 0xFF) {
		case PAGE_NOACCESS:
			strcpy_s(buffer, "NOACCESS");
			break;
		case PAGE_READONLY:
			strcpy_s(buffer, "READONLY");
			break;
		case PAGE_READWRITE:
			strcpy_s(buffer, "READWRITE");
			break;
		case PAGE_WRITECOPY:
			strcpy_s(buffer, "WRITECOPY");
			break;
		case PAGE_EXECUTE:
			strcpy_s(buffer, "EXECUTE");
			break;
		case PAGE_EXECUTE_READ:
			strcpy_s(buffer, "EXECUTE_READ");
			break;
		case PAGE_EXECUTE_READWRITE:
			strcpy_s(buffer, "EXECUTE_READWRITE");
			break;
		case PAGE_EXECUTE_WRITECOPY:
			strcpy_s(buffer, "EXECUTE_WRITECOPY");
			break;
		default:
			sprintf_s(buffer, "UNKNOWN(0x%02X)", protect & 0xFF);
		}

		// 附加属性
		if (protect & PAGE_GUARD)
			strcat_s(buffer, " | GUARD");
		if (protect & PAGE_NOCACHE)
			strcat_s(buffer, " | NOCACHE");
		if (protect & PAGE_WRITECOMBINE)
			strcat_s(buffer, " | WRITECOMBINE");

		return buffer;
	}

	 extern "C" __declspec(dllexport) LPVOID WINAPI NewVirtualAllocEx(
		HANDLE hProcess,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD flAllocationType,
		DWORD flProtect)
	{
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = VIRTUALALLOCEX;
		GetLocalTime(&sendInfo.st);
		sendInfo.argNum = 5;

		const char* paramNames[] = {
			"hProcess", "lpAddress", "dwSize",
			"flAllocationType", "flProtect"
		};
		for (int i = 0; i < 5; i++) {
			strcpy(sendInfo.argName[i], paramNames[i]);
		}

		sprintf(sendInfo.argValue[0], "%p", hProcess);
		sprintf(sendInfo.argValue[1], "%p", lpAddress);
		sprintf(sendInfo.argValue[2], "%zu", dwSize);
		sprintf(sendInfo.argValue[3], "0x%08X", flAllocationType);
		sprintf(sendInfo.argValue[4], "0x%08X", flProtect);

		// 写入共享内存 + 发信号
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		return OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}

	// 原始函数指针声明
	static BOOL(WINAPI* OldWriteProcessMemory)(
		_In_ HANDLE hProcess,
		_In_ LPVOID lpBaseAddress,
		_In_reads_bytes_(nSize) LPCVOID lpBuffer,
		_In_ SIZE_T nSize,
		_Out_opt_ SIZE_T* lpNumberOfBytesWritten
		) = WriteProcessMemory;

	// Hook后函数
	extern "C" __declspec(dllexport) BOOL WINAPI NewWriteProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T * lpNumberOfBytesWritten)
	{
		// 初始化日志结构体
		ZeroMemory(&sendInfo, sizeof(info));
		sendInfo.type = WRITEPROCESSMEMORY;
		GetLocalTime(&sendInfo.st);
		sendInfo.argNum = 5;

		// 参数名
		const char* paramNames[] = {
			"hProcess", "lpBaseAddress", "lpBuffer", "nSize", "CallerPID"
		};
		for (int i = 0; i < 5; i++) {
			strcpy_s(sendInfo.argName[i], paramNames[i]);
		}

		// 参数值
		sprintf_s(sendInfo.argValue[0], "%p", hProcess);
		sprintf_s(sendInfo.argValue[1], "%p", lpBaseAddress);
		sprintf_s(sendInfo.argValue[2], "%p", lpBuffer);
		sprintf_s(sendInfo.argValue[3], "%zu", nSize);
		sprintf_s(sendInfo.argValue[4], "%d", GetCurrentProcessId());

		// 写入共享内存并释放信号量
		if (lpBase) {
			memcpy(lpBase, &sendInfo, sizeof(info));
			ReleaseSemaphore(hSemaphore, 1, NULL);
		}

		// 调用原函数
		return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}



///*
//* ------------------------------------------------------------------------------------------------------
//  ----------------------------------------------- 姚文达 -------------------------------------------------
//  ------------------------------------------------------------------------------------------------------
//*/
//
// 检查某个键被按下还是释放
static SHORT(WINAPI* OldGetAsyncKeyState)(int vKey) = GetAsyncKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetAsyncKeyState(int vKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETASYNCKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//参数名
	sprintf(sendInfo.argName[0], "vKey");
	//参数值
	sprintf(sendInfo.argValue[0], "%d", vKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;
	return OldGetAsyncKeyState(vKey);
}

// 获取指定虚拟键的状态
static SHORT(WINAPI* OldGetKeyState)(int nVirtKey) = GetKeyState;
extern "C" __declspec(dllexport) SHORT WINAPI NewGetKeyState(int nVirtKey) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETKEYSTATE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;
	//参数名
	sprintf(sendInfo.argName[0], "nVirtKey");
	//参数值
	sprintf(sendInfo.argValue[0], "%d", nVirtKey);
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	char desktopPath[MAX_PATH];
	SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);

	char filePath[MAX_PATH];
	snprintf(filePath, sizeof(filePath), "%s\\hook.txt", desktopPath);

	FILE* fp = fopen(filePath, "a");
	if (fp) {
		fprintf(fp, "Type: GetKeyState\n");
		fprintf(fp, "Time: %04d-%02d-%02d %02d:%02d:%02d\n",
			sendInfo.st.wYear, sendInfo.st.wMonth, sendInfo.st.wDay,
			sendInfo.st.wHour, sendInfo.st.wMinute, sendInfo.st.wSecond);

		fprintf(fp, "Arguments:\n");
		for (int i = 0; i < sendInfo.argNum; ++i) {
			fprintf(fp, "  %-8s = %s\n", sendInfo.argName[i], sendInfo.argValue[i]);
		}
		fprintf(fp, "----------------------------------------\n");

		fclose(fp);
	}

	return OldGetKeyState(nVirtKey);
}

// 注册一个系统范围的热键（全局快捷键）
static BOOL(WINAPI* OldRegisterHotKey)(HWND hWnd, int  id, UINT fsModifiers, UINT vk) = RegisterHotKey;
extern "C" __declspec(dllexport) BOOL WINAPI NewRegisterHotKey(HWND hWnd, int  id, UINT fsModifiers, UINT vk) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = REGISTERHOTKEY;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	//参数名
	sprintf(sendInfo.argName[0], "hWnd");
	sprintf(sendInfo.argName[1], "id");
	sprintf(sendInfo.argName[2], "fsModifiers");
	sprintf(sendInfo.argName[3], "vk");
	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", hWnd); // HWND 是指针
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", id);   // id 是 int
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%u", fsModifiers); // UINT
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "0x%X", vk); // 虚拟键码以十六进制显示更清晰

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	//sendInfo.argNum = 0;

	// 调用原始函数
	return OldRegisterHotKey(hWnd, id, fsModifiers, vk);

}

//该函数用于安装一个钩子，它可以拦截并处理各种类型的输入事件或其他消息。
static HHOOK(WINAPI* OldSetWindowsHookExA) (int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) = SetWindowsHookExA;
extern "C" __declspec(dllexport) HHOOK WINAPI NewSetWindowsHookExA(int idHook, HOOKPROC  lpfn, HINSTANCE hmod, DWORD dwThreadId) {
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETWINDOWSHOOKEXA;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;
	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "idHook");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "lpfn");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "hmod");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "dwThreadId");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", idHook);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", lpfn);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", hmod);
	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%lu", dwThreadId);

	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	// 调用原始函数
	return OldSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
}

// 获取鼠标光标坐标
static BOOL(WINAPI* OldGetCursorPos)(LPPOINT) = GetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewGetCursorPos(LPPOINT lpPoint) {
	// 记录调用信息
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = GETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 1;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpPoint");

	// 参数值：先记录原始地址，调用后再记录实际坐标
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpPoint);

	// 调用原始函数获取光标位置
	BOOL result = OldGetCursorPos(lpPoint);

	if (result && lpPoint != NULL) {
		// 如果成功且指针非空，把坐标追加到参数值中
		char temp[128];
		sprintf_s(temp, sizeof(temp), "(%ld, %ld)", lpPoint->x, lpPoint->y);
		strcat_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), temp);
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return result;
}

//将光标移动到屏幕指定位置
static BOOL(WINAPI* OldSetCursorPos)(int, int) = SetCursorPos;
extern "C" __declspec(dllexport) BOOL WINAPI NewSetCursorPos(int X, int Y) {
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = SETCURSORPOS;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 2;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "X");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "Y");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%d", X);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%d", Y);

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldSetCursorPos(X, Y);
}

//用于释放或取消保留调拨的虚拟内存
static BOOL(WINAPI* OldVirtualFree)(LPVOID, SIZE_T, DWORD) = VirtualFree;

extern "C" __declspec(dllexport) BOOL WINAPI NewVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = VIRTUALFREE;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 3;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "lpAddress");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "dwSize");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "dwFreeType");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", lpAddress);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%Iu", dwSize); // SIZE_T 格式化为 %Iu
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "0x%X", dwFreeType);

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);
	sendInfo.argNum = 0;

	return OldVirtualFree(lpAddress, dwSize, dwFreeType);;
}


// 获取系统级别的信息（如进程列表、线程列表、句柄表等）
static  NTSTATUS(NTAPI* OldNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength) = NtQuerySystemInformation;

extern "C" __declspec(dllexport) NTSTATUS NTAPI NewNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength)
{
	// 初始化日志结构体
	memset(&sendInfo, 0, sizeof(sendInfo));
	sendInfo.type = NTQUERYSYSTEMINFORMATION;
	GetLocalTime(&(sendInfo.st));
	sendInfo.argNum = 4;

	// 参数名
	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "SystemInformationClass");
	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "SystemInformation");
	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "SystemInformationLength");
	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "ReturnLength");

	// 参数值
	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%lu", SystemInformationClass);
	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", SystemInformation);
	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%lu", SystemInformationLength);
	if (ReturnLength != NULL) {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%p(=%lu)", ReturnLength, *ReturnLength);
	}
	else {
		sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "NULL");
	}

	// 写入共享内存并通知
	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
	ReleaseSemaphore(hSemaphore, 1, NULL);

	return OldNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);;
}

//从指定进程的虚拟地址空间中读取内存数据

//static NTSTATUS(NTAPI* OldNtReadVirtualMemory)(
//	HANDLE ProcessHandle,
//	PVOID  BaseAddress,
//	PVOID  Buffer,
//	SIZE_T BufferSize,
//	PSIZE_T NumberOfBytesRead) = nullptr;
//
//extern "C" __declspec(dllexport) NTSTATUS NTAPI NewNtReadVirtualMemory(
//	HANDLE ProcessHandle,
//	PVOID  BaseAddress,
//	PVOID  Buffer,
//	SIZE_T BufferSize,
//	PSIZE_T NumberOfBytesRead)
//{
//	// 初始化日志结构体
//	memset(&sendInfo, 0, sizeof(sendInfo));
//	sendInfo.type = NTREADVIRTUALMEMORY;
//	GetLocalTime(&(sendInfo.st));
//	sendInfo.argNum = 5;
//
//	// 参数名
//	sprintf_s(sendInfo.argName[0], sizeof(sendInfo.argName[0]), "ProcessHandle");
//	sprintf_s(sendInfo.argName[1], sizeof(sendInfo.argName[1]), "BaseAddress");
//	sprintf_s(sendInfo.argName[2], sizeof(sendInfo.argName[2]), "Buffer");
//	sprintf_s(sendInfo.argName[3], sizeof(sendInfo.argName[3]), "BufferSize");
//	sprintf_s(sendInfo.argName[4], sizeof(sendInfo.argName[4]), "NumberOfBytesRead");
//
//	// 参数值
//	sprintf_s(sendInfo.argValue[0], sizeof(sendInfo.argValue[0]), "%p", ProcessHandle);
//	sprintf_s(sendInfo.argValue[1], sizeof(sendInfo.argValue[1]), "%p", BaseAddress);
//	sprintf_s(sendInfo.argValue[2], sizeof(sendInfo.argValue[2]), "%p", Buffer);
//	sprintf_s(sendInfo.argValue[3], sizeof(sendInfo.argValue[3]), "%Iu", BufferSize);  // SIZE_T 使用 %Iu
//
//	if (NumberOfBytesRead != NULL) {
//		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "%p(=%Iu)", NumberOfBytesRead, *NumberOfBytesRead);
//	}
//	else {
//		sprintf_s(sendInfo.argValue[4], sizeof(sendInfo.argValue[4]), "NULL");
//	}
//
//	// 写入共享内存并通知
//	memcpy(lpBase, &sendInfo, sizeof(sendInfo));
//	ReleaseSemaphore(hSemaphore, 1, NULL);
//	sendInfo.argNum = 0;
//
//	return OldNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
//}


//---------------------------------------------- main函数 ------------------------------------------------

BOOL WINAPI DllMain(HMODULE hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		InitHook();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OldReadFile, NewReadFile);
		DetourAttach(&(PVOID&)OldWriteFile, NewWriteFile);
		DetourAttach(&(PVOID&)OldGetFileAttributesW, NewGetFileAttributesW);
		DetourAttach(&(PVOID&)OldMoveFileW, NewMoveFileW);
		DetourAttach(&(PVOID&)OldCreateFileA, NewCreateFileA);
		DetourAttach(&(PVOID&)OldSend, NewSend);
		DetourAttach(&(PVOID&)OldSendTo, NewSendTo);
		DetourAttach(&(PVOID&)OldRecv, NewRecv);
		DetourAttach(&(PVOID&)OldRecvFrom, NewRecvFrom);
		DetourAttach(&(PVOID&)OldConnect, NewConnect);
		DetourAttach(&(PVOID&)OldWSAConnect, NewWSAConnect);
		DetourAttach(&(PVOID&)Old_getaddrinfo, New_getaddrinfo);
		DetourAttach(&(PVOID&)OldSocket, NewSocket);
		DetourAttach(&(PVOID&)OldCloseSocket, NewCloseSocket);
		DetourAttach(&(PVOID&)OldCreateProcessW, NewCreateProcessW);
		DetourAttach(&(PVOID&)OldCreateProcessA, NewCreateProcessA);
		DetourAttach(&(PVOID&)OldCreateThread, NewCreateThread);
		DetourAttach(&(PVOID&)OldExitThread, NewExitThread);
		DetourAttach(&(PVOID&)OldLoadLibraryExA, NewLoadLibraryExA);
		DetourAttach(&(PVOID&)OldGetProcAddress, NewGetProcAddress);
		DetourAttach(&(PVOID&)OldGetAsyncKeyState, NewGetAsyncKeyState);
		DetourAttach(&(PVOID&)OldGetKeyState, NewGetKeyState);
		DetourAttach(&(PVOID&)OldRegisterHotKey, NewRegisterHotKey);
		DetourAttach(&(PVOID&)OldSetWindowsHookExA, NewSetWindowsHookExA);
		DetourAttach(&(PVOID&)OldGetCursorPos, NewGetCursorPos);
		DetourAttach(&(PVOID&)OldSetCursorPos, NewSetCursorPos);
		DetourAttach(&(PVOID&)OldVirtualFree, NewVirtualFree);
		DetourAttach(&(PVOID&)OldVirtualAllocEx, NewVirtualAllocEx);
		DetourAttach(&(PVOID&)OldNtQuerySystemInformation, NewNtQuerySystemInformation);
		DetourAttach(&(PVOID&)OldWriteProcessMemory, NewWriteProcessMemory);
		//DetourAttach(&(PVOID&)OldNtReadVirtualMemory, NewNtReadVirtualMemory);
		DetourAttach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
		DetourTransactionCommit();
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)OldReadFile, NewReadFile);
		DetourDetach(&(PVOID&)OldWriteFile, NewWriteFile);
		DetourDetach(&(PVOID&)OldGetFileAttributesW, NewGetFileAttributesW);
		DetourDetach(&(PVOID&)OldMoveFileW, NewMoveFileW);
		DetourDetach(&(PVOID&)OldCreateFileA, NewCreateFileA);
		DetourDetach(&(PVOID&)OldSend, NewSend);
		DetourDetach(&(PVOID&)OldSendTo, NewSendTo);
		DetourDetach(&(PVOID&)OldRecv, NewRecv);
		DetourDetach(&(PVOID&)OldRecvFrom, NewRecvFrom);
		DetourDetach(&(PVOID&)OldConnect, NewConnect);
		DetourDetach(&(PVOID&)OldWSAConnect, NewWSAConnect);
		DetourDetach(&(PVOID&)Old_getaddrinfo, New_getaddrinfo);
		DetourDetach(&(PVOID&)OldSocket, NewSocket);
		DetourAttach(&(PVOID&)OldCloseSocket, NewCloseSocket);
		DetourDetach(&(PVOID&)OldCreateProcessW, NewCreateProcessW);
		DetourDetach(&(PVOID&)OldCreateProcessA, NewCreateProcessA);
		DetourDetach(&(PVOID&)OldCreateThread, NewCreateThread);
		DetourDetach(&(PVOID&)OldExitThread, NewExitThread);
		DetourDetach(&(PVOID&)OldLoadLibraryExA, NewLoadLibraryExA);
		DetourDetach(&(PVOID&)OldGetProcAddress, NewGetProcAddress);
		DetourDetach(&(PVOID&)OldGetAsyncKeyState, NewGetAsyncKeyState);
		DetourDetach(&(PVOID&)OldGetKeyState, NewGetKeyState);
		DetourDetach(&(PVOID&)OldRegisterHotKey, NewRegisterHotKey);
		DetourDetach(&(PVOID&)OldSetWindowsHookExA, NewSetWindowsHookExA);
		DetourDetach(&(PVOID&)OldGetCursorPos, NewGetCursorPos);
		DetourDetach(&(PVOID&)OldSetCursorPos, NewSetCursorPos);
		DetourDetach(&(PVOID&)OldVirtualFree, NewVirtualFree);
		DetourDetach(&(PVOID&)OldNtQuerySystemInformation, NewNtQuerySystemInformation);
		DetourDetach(&(PVOID&)OldVirtualAllocEx, NewVirtualAllocEx);
		DetourDetach(&(PVOID&)OldWriteProcessMemory, NewWriteProcessMemory);
		//DetourDetach(&(PVOID&)OldNtReadVirtualMemory, NewNtReadVirtualMemory);
		DetourDetach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
		DetourTransactionCommit();
		break;
	}
	}
	return true;
}
