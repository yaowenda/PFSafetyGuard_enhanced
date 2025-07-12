#include "mainwindow.h"
#include "ui_mainwindow.h"
extern info recvInfo;
char priorityStr[8][20] = { "NORMAL", "IDLE" , "REALTIME", "HIGH", "NULL", "ABOVENORMAL", "BELOWNORMAL" };
void myThread::run() {
    int lastType = -1;
    SYSTEMTIME lastSt;
    //QString temp = QString(QLatin1String(fileName));
    //emit newValue(QString(QLatin1String(fileName)));
    //msleep(1500);
    emit newProcessName(QString(QLatin1String(fileName)));
    HANDLE hSemaphore = CreateSemaphore(NULL, 0, 1, L"mySemaphore");
    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(info), L"ShareMemory");
    LPVOID lpBase = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    STARTUPINFOA startupInfo = { 0 };
    PROCESS_INFORMATION  processInformation = { 0 };
    char temp[4096] = {0};
    char moduleName[256];
    HMODULE hMod[100];
    DWORD cbNeeded;
    int moduleNum;
    // *****需要修改部分****
    // 启动注射器进程
    BOOL bSuccess = CreateProcessA("D:\\PFSafetyGuard\\PFSafetyGuard\\syringe\\x64\\Release\\syringe.exe", filePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInformation);
    sprintf(temp, "%d", processInformation.dwProcessId);
    emit newProcessID(QString(QLatin1String(temp)));
    sprintf(temp, "%s", priorityStr[GetProcessPriority(processInformation.hProcess)]);
    emit newProcessPriority(QString(QLatin1String(temp)));
    memset(temp, 0, sizeof(temp));// temp清零
    msleep(500);
    if (EnumProcessModules(processInformation.hProcess, hMod, sizeof(hMod), &cbNeeded))
    {
        // 模块个数
        moduleNum = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < moduleNum; i++) {
            GetModuleFileNameA(hMod[i], moduleName, 256);
            strcat(temp, moduleName);
            strcat(temp, "\n");
        }
        emit newProcessModules(QString(QLatin1String(temp)));
    }
    msleep(1500);
    while (running) {
        //for (int i = 0; i < 2; i++) {
        //	emit newValue(QString::number(i));
        //	msleep(500);
        //}
        // 等待500ms
        if (WaitForSingleObject(hSemaphore, 10) == WAIT_OBJECT_0) {
            memcpy(&recvInfo, lpBase, sizeof(info));
            if (lastSt.wMilliseconds == recvInfo.st.wMilliseconds && lastSt.wSecond == recvInfo.st.wSecond && lastType == recvInfo.type) {
                continue;
            }
            lastSt = recvInfo.st;
            lastType = recvInfo.type;
            emit newInfo();
            checkFunc();
        } else {
            DWORD error = GetLastError();
            if (error != 0){ //说明有错误
                qDebug() << "错误" << error;
            }

        }
    }
    quit();
}

void  myThread::getFileName(char *filePath, char *fileName) {
    int len = strlen(filePath);
    while (filePath[len - 1] != '\\') {
        len--;
    }
    strcpy(fileName, filePath + len);
}

void myThread::init(char * path) {
    running = true;
    memset(filePath, 0, sizeof(filePath));
    memset(fileName, 0, sizeof(fileName));
    strcpy(filePath, path);
    for (int i = 0; filePath[i] != 0; i++) {
        if (filePath[i] == '/') {
            filePath[i] = '\\';
        }
    }
    getFileName(filePath, fileName);
}

void myThread::stopThread() {
    running = false;
}

int myThread::GetProcessPriority(HANDLE hProcess)
{
    switch (GetPriorityClass(hProcess))
    {
    case NORMAL_PRIORITY_CLASS:return 0;
    case  IDLE_PRIORITY_CLASS:return 1;
    case REALTIME_PRIORITY_CLASS:return 2;
    case HIGH_PRIORITY_CLASS:return 3;
    case ABOVE_NORMAL_PRIORITY_CLASS:return 5;
    case BELOW_NORMAL_PRIORITY_CLASS:return 6;
    default:return 4;
    }
}
void myThread::checkFunc() {
    unsigned  temp;
    switch (recvInfo.type) //此结构体中的type就是目标程序调用的Windows API
    {

        /**----------------------------------------------------------------------------------------------
           -------------------------------------王博-----------------------------------------------------
           --------------------------------------------------------------------------------------------- */
    case READFILE: {
        char filePath[260] = {0};
        strncpy(filePath, recvInfo.argValue[0], sizeof(filePath) - 1);

        QString path = QString::fromLocal8Bit(filePath).toLower(); // 路径转为小写统一处理

        // 1. 检测敏感系统注册表文件
        if (path.contains("c:\\windows\\system32\\config\\sam")) {
            emit newInfo(QString::fromUtf8("警告：读取敏感系统文件SAM"), 2);
        }
        // 2. 检测 hosts 文件（可能修改网络解析行为）
        else if (path.endsWith("etc\\hosts") || path.contains("drivers\\etc\\hosts")) {
            emit newInfo(QString::fromUtf8("警告：正在读取主机文件（可能是DNS操作）：") + QString::fromLocal8Bit(filePath), 2);
        }
        // 3. 检测系统配置文件（如 win.ini）
        else if (path.endsWith("win.ini") || path.endsWith("system.ini")) {
            emit newInfo(QString::fromUtf8("警告：正在读取旧系统配置文件：") + QString::fromLocal8Bit(filePath), 2);
        }
        // 4. 检测 .ini/.config 文件
        else if (path.endsWith(".ini") || path.endsWith(".config")) {
            emit newInfo(QString::fromUtf8("警告: 正在读取配置文件: ") + QString::fromLocal8Bit(filePath), 2);
        }
        // 5. 检测用户文件（文档、桌面等）
        else if (path.contains("users\\") &&
                 (path.contains("documents") || path.contains("desktop"))) {
            emit newInfo(QString::fromUtf8("警告：正在读取用户个人文件： ") + QString::fromLocal8Bit(filePath), 2);
        }
        // 6. 检测 temp 目录中的测试/临时文件
        else if (path.contains("\\temp\\") || path.contains("\\tmp\\")) {
            emit newInfo(QString::fromUtf8("注意：读取临时文件：") + QString::fromLocal8Bit(filePath), 1);
        }
        // 7. 正常读取行为提示
        else {
            emit newInfo(QString::fromUtf8("注意：文件读取操作： ") + QString::fromLocal8Bit(filePath), 1);
        }

        break;
    }

    case WRITEFILE: {
        // 读取写入的文件句柄，尝试获取文件路径（需要注射器传递路径，或由注射器先转成路径传过来）
        char filePath[260] = {0};
        // 这里假设注射器把文件路径放在 argValue[0]，如果是句柄，则需要转路径
        strncpy(filePath, recvInfo.argValue[0], sizeof(filePath) - 1);

        // 简单示例：检测写入可执行文件
        if (strstr(filePath, ".exe") || strstr(filePath, ".dll") || strstr(filePath, ".ocx")) {
            emit newInfo(QString::fromUtf8("警报: 正在修改可执行文件： ") + QString(filePath) + "\n", 2);
        }
        // 也可检测写入系统关键路径
        else if (strstr(filePath, "C:\\Windows\\System32")) {
            emit newInfo(QString::fromUtf8("警告：正在写入系统文件夹") + QString(filePath) + "\n", 2);
        }
        // 检测写入多个目录的情况
        else {
            static std::set<std::string> writtenFolders;
            std::string folder;
            getLastFolder(filePath, folder);
            writtenFolders.insert(folder);
            if (writtenFolders.size() >= 2) {
                emit newInfo(QString::fromUtf8("警告：在多个文件夹中写入文件！\n"), 2);
            }
        }
        break;
    }
    case GETFILEATTRIBUTESW: {
        char* filePath = recvInfo.argValue[0];

        // 简单安全检查示例：检测是否访问了系统敏感目录或隐藏文件
        if (strstr(filePath, "C:\\Windows\\System32") || strstr(filePath, "C:\\Windows\\SysWOW64")) {
            emit newInfo(QString::fromUtf8("警告：正在访问系统文件夹： ") + QString(filePath) + "\n", 2);
        }

        // 检查是否访问隐藏文件（假设文件名以 "." 开头或其他逻辑）
        if (filePath[0] == '.') {
            emit newInfo(QString::fromUtf8("警告：正在访问隐藏文件或系统文件： ") + QString(filePath) + "\n", 2);
        }

        // 也可以结合返回结果分析是否文件存在或是否有访问权限
        // result = recvInfo.returnValue (需要Hook中传回来）
        break;
    }
    case MOVEFILEW: {
        QString oldName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString newName = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 定义敏感目录列表
        QStringList sensitiveDirs = {
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Program Files",
            "C:\\Program Files (x86)",
            "C:\\Users\\Default",
            "C:\\Users\\Public",
            "C:\\Users\\%USERNAME%\\AppData"  // 可用 QDir::homePath() 替代 %USERNAME%
        };

        // 检查 oldName 或 newName 是否以敏感目录开头
        for (const QString& dir : sensitiveDirs) {
            QString normDir = dir;
            if (normDir.contains("%USERNAME%", Qt::CaseInsensitive)) {
                normDir.replace("%USERNAME%", QDir::home().dirName(), Qt::CaseInsensitive);
            }

            if (oldName.startsWith(normDir, Qt::CaseInsensitive) ||
                newName.startsWith(normDir, Qt::CaseInsensitive)) {
                emit newInfo(QString::fromUtf8("警告：文件在敏感目录中移动或重命名\nOld Path: ") + oldName + "\nNew Path: " + newName, 2);
                break;
            }
        }

        break;
    }
    case CREATEFILEA: {
        QString fileName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        DWORD desiredAccess = strtoul(recvInfo.argValue[1], nullptr, 16);
        DWORD creationDisposition = strtoul(recvInfo.argValue[4], nullptr, 16);

        // 安全行为分析 1：检测是否以写入权限打开系统关键目录下的文件
        QStringList criticalDirs = {
            "C:\\Windows", "C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)"
        };
        for (const QString& path : criticalDirs) {
            if (fileName.startsWith(path, Qt::CaseInsensitive)) {
                if (desiredAccess & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA)) {
                    emit newInfo(QString::fromUtf8("警告：试图写入关键系统文件：") + fileName, 2);
                    break;
                }
            }
        }

        // 安全行为分析 2：检测是否以 CREATE_ALWAYS 或 TRUNCATE_EXISTING 方式打开文件（可能覆盖文件）
        if (creationDisposition == CREATE_ALWAYS || creationDisposition == TRUNCATE_EXISTING) {
            emit newInfo(QString::fromUtf8("警告：以覆盖处理打开的文件：") + fileName, 2);
        }

        break;
    }

    case SEND: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 行为1：检测敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("cmd", Qt::CaseInsensitive)) {
            emit newInfo("警告：在发送缓冲区中检测到敏感关键字: \"" + data.left(50) + "\"", 2);
        }

        // 行为2：检测是否尝试上传大量数据（如 >1024 字节）
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);
        if (ok && length > 1024) {
            emit newInfo(QString("警告：已发送大负载（大小：%1字节）").arg(length), 1);
        }

        break;
    }
    case SENDTO: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 行为1：检测是否发送敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("secret", Qt::CaseInsensitive)) {
            emit newInfo(QString::fromUtf8("警告：在发送到缓冲区中检测到敏感关键字 \"") + data.left(50) + "\"", 2);
        }

        // 行为2：检测UDP是否尝试进行端口扫描（数据包小且频繁，可结合实际检测频率）
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);
        if (ok && length < 10) {
            emit newInfo(QString::fromUtf8("Notice: Small UDP payload sent (possible port scan)"), 1);
        }

        break;
    }
    case RECV: {
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);

        // 行为1：检测接收到的数据包中是否包含敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||
            data.contains("token", Qt::CaseInsensitive) ||
            data.contains("secret", Qt::CaseInsensitive) ||
            data.contains("confidential", Qt::CaseInsensitive)) {
            emit newInfo(QString::fromUtf8("警告：在recv缓冲区中检测到敏感关键字： \"") + data.left(50) + "\"", 2);
        }

        // 行为2：检测接收异常大数据包，可能存在DoS攻击风险
        if (ok && length > 1024) {
            emit newInfo(QString::fromUtf8("注意：收到大数据包（%1字节），可能是DoS攻击").arg(length), 1);
        }

        break;
    }
    case RECVFROM: {
        // 从参数中提取接收到的数据内容，转换为本地编码（一般是GBK/GB2312）
        QString data = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 尝试将数据长度（字符串）转换为整数
        bool ok = false;
        int length = QString(recvInfo.argValue[2]).toInt(&ok);

        // 提取发送方地址信息（如 IP:PORT）
        QString fromAddr = QString::fromLocal8Bit(recvInfo.argValue[4]);

        // 行为检测1：判断数据中是否包含敏感关键字
        if (data.contains("password", Qt::CaseInsensitive) ||       // 检测 password
            data.contains("token", Qt::CaseInsensitive) ||          // 检测 token
            data.contains("secret", Qt::CaseInsensitive) ||         // 检测 secret
            data.contains("confidential", Qt::CaseInsensitive)) {   // 检测 confidential
            // 如果命中敏感关键字，触发二级安全警告，并输出前50个字符及来源地址
            emit newInfo("Warning: Sensitive keyword detected in recvfrom buffer: \""
                             + data.left(50) + "\" from " + fromAddr, 2);
        }

        // 行为检测2：判断数据包长度是否异常大，可能是拒绝服务攻击
        if (ok && length > 1024) {
            // 如果数据长度大于1024字节，提示可能是DoS攻击行为
            emit newInfo(QString("Notice: Large data packet received (%1 bytes) from %2, possible DoS attack")
                             .arg(length).arg(fromAddr), 1);
        }

        break;
    }

    case CONNECT: {
        QString addrPort = QString::fromLocal8Bit(recvInfo.argValue[1]);
        QStringList parts = addrPort.split(':');
        QString ipStr = parts.value(0);
        bool ok = false;
        int port = parts.value(1).toInt(&ok);

        // 行为检测1：本地地址
        if (ipStr == "127.0.0.1") {
            emit newInfo(QString::fromUtf8("注意：连接到本地主机（%1:%2）").arg(ipStr).arg(port), 1);
        }
        // 行为检测2：内网私有地址
        else if (ipStr.startsWith("10.") ||
                 ipStr.startsWith("192.168.") ||
                 (ipStr.startsWith("172.") && port >= 16 && port <= 31)) {
            emit newInfo(QString::fromUtf8("注意：连接到私有网络IP （%1:%2）").arg(ipStr).arg(port), 1);
        }
        // 行为检测3：公网敏感端口
        else {
            QString msg = QString::fromUtf8("警告：连接到外部IP %1:%2").arg(ipStr).arg(port);
            QList<int> sensitivePorts = {22, 23, 21, 445, 3389, 139, 5900};  // SSH, Telnet, FTP, SMB, RDP, NetBIOS, VNC

            if (ok && sensitivePorts.contains(port)) {
                emit newInfo(msg + " on sensitive port", 2);  // 二级告警
            } else {
                emit newInfo(msg, 1);  // 普通连接警告
            }
        }

        break;
    }

    case WSACONNECT: {
        // 解析目标IP和端口，格式示例 "192.168.10.128:5555"
        QString addrPort = QString::fromLocal8Bit(recvInfo.argValue[1]);
        QStringList parts = addrPort.split(':');
        QString ipStr = parts.value(0);
        bool ok = false;
        int port = parts.value(1).toInt(&ok);

        // 检测是否连接本地回环地址
        if (ipStr == "127.0.0.1") {
            emit newInfo(QString::fromUtf8("注意：WSAConect到本地主机（%1:%2）").arg(ipStr).arg(port), 1);
        }
        // 检测是否连接私有网络地址
        else if (ipStr.startsWith("10.") ||
                 ipStr.startsWith("192.168.") ||
                 (ipStr.startsWith("172.") && (port >= 16 && port <= 31))) {
            emit newInfo(QString::fromUtf8("注意：WSAConect连接到私有网络IP （%1:%2）").arg(ipStr).arg(port), 1);
        }
        else {
            QString msg = QString::fromUtf8("注意: 连接到外部IP %1:%2").arg(ipStr).arg(port);
            QList<int> sensitivePorts = {23, 3389, 22, 5900, 21, 445, 139};
            if (ok && sensitivePorts.contains(port)) {
                emit newInfo(msg + " on sensitive port", 2);
            } else {
                emit newInfo(msg, 1);
            }
        }

        break;
    }

    case GETADDRINFO: {
        QString nodeName = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString serviceName = QString::fromLocal8Bit(recvInfo.argValue[1]);

        // 敏感关键字检测
        if (nodeName.contains("vpn", Qt::CaseInsensitive) ||
            nodeName.contains("proxy", Qt::CaseInsensitive) ||
            nodeName.contains("tor", Qt::CaseInsensitive)) {
            emit newInfo(QString::fromUtf8("警告：检测到潜在匿名服务的DNS查询：") + nodeName, 2);
        }

        // 可疑端口检测（服务名）
        if (serviceName == "6666" || serviceName == "31337") {
            emit newInfo(QString::fromUtf8("警告：getaddrinfo中请求的可疑服务端口：") + serviceName, 2);
        }

        // 长域名异常检测（DNS隧道、C2）
        if (nodeName.length() > 50) {
            emit newInfo(QString::fromUtf8("注意：查询长域名（可能是隧道）： ") + nodeName.left(60), 1);
        }

        break;
    }
    case SOCKET_CREATE: {
        bool ok1 = false, ok2 = false, ok3 = false;
        int af = QString(recvInfo.argValue[0]).toInt(&ok1, 16);       // 地址族
        int type = QString(recvInfo.argValue[1]).toInt(&ok2, 16);     // 套接字类型
        int protocol = QString(recvInfo.argValue[2]).toInt(&ok3, 16); // 协议

        if (!ok1 || !ok2 || !ok3) {
            emit newInfo(QString::fromUtf8("错误：解析套接字参数失败。"),2);
            break;
        }

        QString familyStr, typeStr, protoStr;

        // 地址族判断
        switch (af) {
        case AF_INET: familyStr = "AF_INET (IPv4)"; break;
        case AF_INET6: familyStr = "AF_INET6 (IPv6)"; break;
        case AF_UNSPEC: familyStr = "AF_UNSPEC"; break;
        default: familyStr = QString::fromUtf8("Unknown (%1)").arg(af); break;
        }

        // 套接字类型判断
        switch (type) {
        case SOCK_STREAM: typeStr = "SOCK_STREAM (TCP)"; break;
        case SOCK_DGRAM: typeStr = "SOCK_DGRAM (UDP)"; break;
        case SOCK_RAW: typeStr = "SOCK_RAW (RAW)"; break;
        default: typeStr = QString::fromUtf8("Unknown (%1)").arg(type); break;
        }

        // 协议判断
        switch (protocol) {
        case IPPROTO_TCP: protoStr = "IPPROTO_TCP"; break;
        case IPPROTO_UDP: protoStr = "IPPROTO_UDP"; break;
        case IPPROTO_ICMP: protoStr = "IPPROTO_ICMP"; break;
        case 0: protoStr = "Default"; break;
        default: protoStr = QString::fromUtf8("Unknown (%1)").arg(protocol); break;
        }

        // 警告 RAW Socket（可能存在嗅探/扫描行为）
        if (type == SOCK_RAW) {
            emit newInfo(QString::fromUtf8("警告：已创建原始套接字-潜在的嗅探/扫描行为！"), 2);
        }

        // 普通信息
        emit newInfo(QString::fromUtf8("创建套接字。家庭：%1，类型：%2，协议：%3")
                         .arg(familyStr).arg(typeStr).arg(protoStr), 0);

        break;
    }
    case SOCKET_CLOSE: {
        QString socketStr = QString::fromLocal8Bit(recvInfo.argValue[0]);
        bool ok = false;
        qlonglong socketVal = socketStr.toLongLong(&ok, 16);  // 16 进制解析

        // 检查 socket 是否在已知连接中（需要配合全局 socket 管理机制）
        if (ok && socketVal == 0) {
            emit newInfo(QString::fromUtf8("警告：在NULL套接字句柄上调用closesocket"), 2);
        }

        static QMap<qlonglong, QDateTime> socketCloseMap;
        QDateTime now = QDateTime::currentDateTime();

        // 检查该 socket 是否频繁关闭
        if (socketCloseMap.contains(socketVal)) {
            qint64 diff = socketCloseMap[socketVal].msecsTo(now);
            if (diff < 1000) {
                emit newInfo(QString::fromUtf8("可疑行为：套接字%1在短时间内反复关闭 (%2 ms)").arg(socketStr).arg(diff), 1);
            }
        }

        socketCloseMap[socketVal] = now;

        emit newInfo(QString::fromUtf8("注意: Socket连接关闭: %1").arg(socketStr), 0);
        break;
    }




        /**----------------------------------------------------------------------------------------------
           -------------------------------------沈丽彤-----------------------------------------------------
           --------------------------------------------------------------------------------------------- */

        // 进程创建监控 (CreateProcessW/A, ShellExecuteW)
        // 进程创建监控（CreateProcessW/A，ShellExecuteW）
        // 进程创建监控（CreateProcessW/A，ShellExecuteW）
    case CREATEPROCESSW:
    case CREATEPROCESSA:
    case SHELLEXECUTEW: {
        char* procName = recvInfo.argValue[1]; // 直接获取进程名

        // 内联恶意进程检测（替代isMaliciousProcess函数）
        const char* blacklist[] = {"cmd.exe", "powershell.exe", "wscript.exe", nullptr};
        bool isMalicious = false;
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(procName, blacklist[i])) {
                isMalicious = true;
                break;
            }
        }

        if (isMalicious) {
            emit newInfo(QString::fromUtf8("警告：已创建可疑进程： %1\n").arg(procName), 2);
        }
        break;
    }
    // 线程操作监控 (CreateThread, ExitThread)
    // 线程创建监控 (CreateThread)
    case CREATETHREAD: {
        DWORD threadStartAddr = strtoul(recvInfo.argValue[2], NULL, 16);

        // 内联shellcode检测逻辑
        bool isShellcode = false;
        if (threadStartAddr != 0 && threadStartAddr >= 0x1000) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)threadStartAddr, &mbi, sizeof(mbi))) {
                isShellcode = !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
            }
        }

        if (isShellcode) {
            emit newInfo(QString::fromUtf8("警告：可能通过CreateThread执行shellcode!\n"), 2);
        }
        break;
    }
    case EXITTHREAD: {
        DWORD exitCode = strtoul(recvInfo.argValue[0], NULL, 16);  // 第二个参数为 exitCode

        if (exitCode != 0) {
            emit newInfo(QStringLiteral("警告：检测到线程异常退出，ExitThread 使用非零退出码！\n"), 2);
        }
        break;
    }
    // DLL 加载监控 (LoadLibraryW/ExW, GetProcAddress)
    case LOADLIBRARYEXA: {
        QString dllPath = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString flagInfo = QString::fromLatin1(recvInfo.argValue[1]);

        // 判断是否使用了加载外部 DLL 且带有可疑加载标志
        bool isSuspicious = false;

        if (!dllPath.isEmpty()) {
            QFileInfo fi(dllPath);
            QString absPath = fi.absoluteFilePath();

            // 1. 是否位于可疑目录（如用户临时目录、下载目录）
            if (absPath.contains("Temp", Qt::CaseInsensitive) ||
                absPath.contains("Downloads", Qt::CaseInsensitive) ||
                absPath.contains("Users", Qt::CaseInsensitive)){
                isSuspicious = true;
            }

            // 2. 是否使用了 ALTERED_SEARCH_PATH 等不常用标志
            if (flagInfo.contains("ALTERED_SEARCH_PATH", Qt::CaseInsensitive) ||
                flagInfo.contains("DONT_RESOLVE", Qt::CaseInsensitive)) {
                isSuspicious = true;
            }
        }

        if (isSuspicious) {
            emit newInfo(QString::fromUtf8("警告：检测到可疑 DLL 加载行为（LoadLibraryExA）！\n路径：%1\n标志：%2\n")
                             .arg(dllPath, flagInfo), 2);
        }
        break;
    }
    case GETPROCADDRESS: {
        if (!recvInfo.argValue[1]) break;  // 检查空指针

        const char* funcName = recvInfo.argValue[1];

        // 内联危险API检测逻辑
        bool isDangerous = false;
        const char* blacklist[] = {
            "WriteProcessMemory",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "LoadLibrary",
            nullptr  // 结束标记
        };

        // 检查黑名单
        for (int i = 0; blacklist[i]; i++) {
            if (strstr(funcName, blacklist[i]) != nullptr) {
                isDangerous = true;
                break;
            }
        }

        if (isDangerous) {
            emit newInfo(QString(QLatin1String("Warning: Dangerous API resolved: %1\n")).arg(funcName),2);
        }
        break;
    }

        // 进程注入监控 (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    case VIRTUALALLOCEX: {
        QString procInfo = QString::fromLocal8Bit(recvInfo.argValue[0]);
        QString protectStr = QString::fromLocal8Bit(recvInfo.argValue[4]);

        // 是否远程分配
        bool isRemote = !procInfo.contains(QString::number(GetCurrentProcessId()));

        // 是否含可执行权限
        bool isExecutable = protectStr.contains("EXECUTE");

        QString msg;
        int level = 1;

        if (isRemote && isExecutable) {
            msg = QString("Warning: VirtualAllocEx on another process with executable memory: %1").arg(procInfo);
            level = 2;
        } else if (isRemote) {
            msg = QString("Notice: VirtualAllocEx on another process (non-executable): %1").arg(procInfo);
            level = 1;
        } else {
            msg = QString("Info: VirtualAllocEx used in current process: %1").arg(procInfo);
            level = 0;
        }

        emit newInfo(msg, level);
        break;
    }

    case WRITEPROCESSMEMORY: {
        temp = strtoul(recvInfo.argValue[0], NULL, 16);
        if (hProcess != GetCurrentProcess()) {
            emit newInfo(QString("Warning: WriteProcessMemory called on external process!\n"), 2);
        }
        break;
    }
    case CREATEREMOTETHREAD: {
        temp = strtoul(recvInfo.argValue[0], NULL, 16);
        if (hProcess != GetCurrentProcess()) {
            emit newInfo(QString("Warning: CreateRemoteThread called on external process!\n"), 2);
        }
        break;
    }

    /*----------------------------------------------------------------------------------------------
     -------------------------------------------姚文达-----------------------------------------------
    ------------------------------------------------------------------------------------------------*/

    //检测有没有监控键盘
    case GETASYNCKEYSTATE: {
        static QTime lastWarningTime = QTime::currentTime();
        static int keyCount = 0;

        // 获取当前时间
        QTime currentTime = QTime::currentTime();

        // 如果在1秒内检测到过多的GetAsyncKeyState调用
        if (lastWarningTime.msecsTo(currentTime) < 5000) {
            keyCount++;

            // 如果5秒内调用次数超过阈值（例如10次）
            if (keyCount > 1) {
                emit newInfo(QString::fromUtf8("警报: 检测到潜在的键盘记录活动！短时间内多次调用GetAsyncKeyState\n"), 2);

                // 记录可疑的键值
                QString keyValue = QString::fromLatin1(recvInfo.argValue[0]);
                emit newInfo(QString("监控到有键盘值被记录: %1\n").arg(keyValue), 2);

                // 重置计数器
                keyCount = 0;
            }
        } else {
            // 重置计数器和时间
            keyCount = 1;
            lastWarningTime = currentTime;
        }

        // 特别关注某些敏感键位的监控
        int vKey = atoi(recvInfo.argValue[0]);
        if ((vKey >= 0x41 && vKey <= 0x5A) ||  // A-Z
            vKey == VK_RETURN ||
            vKey == VK_BACK) {
            emit newInfo(QString(QLatin1String("警告：程序正在监控键盘输入！\n")), 2);
        }
        break;
    }

    //检测有没有监控键盘
    case GETKEYSTATE: {
        static QTime lastTime = QTime::currentTime();
        static int count = 0;

        QTime now = QTime::currentTime();

        if (lastTime.msecsTo(now) < 5000) {
            count++;

            // 如果5秒内调用超过2次，发出警报（可调整）
            if (count > 5) {
                emit newInfo(QString::fromUtf8("警报: 可疑程序频繁调用 GetKeyState，疑似在监控按键状态！\n"), 2);

                QString keyValue = QString::fromLatin1(recvInfo.argValue[0]);
                emit newInfo(QString::fromUtf8("检测到被频繁监控的按键值: %1\n").arg(keyValue), 2);

                count = 0;
            }
        } else {
            count = 1;
            lastTime = now;
        }

        // 重点关注 A-Z、Enter、Backspace
        int vKey = atoi(recvInfo.argValue[0]);
        if ((vKey >= 0x41 && vKey <= 0x5A) || vKey == VK_RETURN || vKey == VK_BACK) {
            emit newInfo(QString::fromUtf8("警告：程序正在读取键盘状态（GetKeyState）！\n"), 2);
        }

        break;
    }

    //检测短时间内频繁注册热键的行为   检测是否注册了特定敏感热键组合
    case REGISTERHOTKEY: {
        static QTime lastHotkeyTime = QTime::currentTime();
        static int hotkeyCount = 0;

        QTime now = QTime::currentTime();

        if (lastHotkeyTime.msecsTo(now) < 5000) {
            hotkeyCount++;

            if (hotkeyCount >= 1) {
                emit newInfo(QString::fromUtf8("警报：检测到程序在短时间内注册全局热键，可能劫持系统快捷键！\n"), 2);
                QString detail = QString::fromUtf8("热键参数: id=%1, 修饰符=%2, 虚拟键=%3\n")
                                     .arg(QString::fromLatin1(recvInfo.argValue[1]))
                                     .arg(QString::fromLatin1(recvInfo.argValue[2]))
                                     .arg(QString::fromLatin1(recvInfo.argValue[3]));
                emit newInfo(detail, 2);

                hotkeyCount = 0;  // 重置
            }
        } else {
            //如果距离上次热键注册的时间超过 5 秒
            hotkeyCount = 1;// 重置计数器为 1 (当前这次注册算第一次)
            lastHotkeyTime = now;// 更新上次热键注册的时间
        }

        // 针对某些敏感组合特别警告
        UINT fsModifiers = atoi(recvInfo.argValue[2]);
        int vKey = 0;
        sscanf(recvInfo.argValue[3], "0x%X", &vKey); // 从十六进制解析虚拟键码

        if ((fsModifiers & MOD_ALT) && (fsModifiers & MOD_CONTROL) && vKey == VK_DELETE) {
            emit newInfo(QString::fromUtf8("严重警告：程序尝试注册 Ctrl+Alt+Del 快捷键，可能用于阻断任务管理器！\n"), 2);
        }

        if ((fsModifiers & MOD_ALT) && vKey == VK_F4) {
            emit newInfo(QString::fromUtf8("警告：程序注册 Alt+F4 快捷键，可能用于拦截窗口关闭操作！\n"), 2);
        }

        break;
    }


    case SETWINDOWSHOOKEXA: {
        static QTime lastHookTime = QTime::currentTime();
        static int hookCount = 0;

        QTime now = QTime::currentTime();

        if (lastHookTime.msecsTo(now) < 5000) {
            hookCount++;
            if (hookCount > 2) {
                emit newInfo(QString::fromUtf8("警报：检测到短时间内多次调用 SetWindowsHookExA，可能存在钩子注入！\n"), 2);

                QString detail = QString::fromUtf8("钩子类型: %1，线程ID: %2\n")
                                     .arg(QString::fromLatin1(recvInfo.argValue[0]))
                                     .arg(QString::fromLatin1(recvInfo.argValue[3]));
                emit newInfo(detail, 2);

                hookCount = 0;
            }
        } else {
            hookCount = 1;
            lastHookTime = now;
        }

        int idHook = atoi(recvInfo.argValue[0]);
        if (idHook == WH_CBT) {
            emit newInfo(QString::fromUtf8("警告：检测到程序安装了 WH_CBT 钩子！\n"), 2);
        }
        else if (idHook == WH_GETMESSAGE) {
            emit newInfo(QString::fromUtf8("警告：检测到程序安装了 WH_GETMESSAGE 钩子！\n"), 2);
        }
        else if (idHook == WH_CALLWNDPROC) {
            emit newInfo(QString::fromUtf8("警告：检测到程序安装了 WH_CALLWNDPROC 钩子！\n"), 2);
        }
        break;
    }

    case GETCURSORPOS: {
        QString argVal = QString::fromLatin1(recvInfo.argValue[0]); // 类似 "0x12345678(100, 200)"
        emit newInfo(QString::fromUtf8("检测到调用 GetCursorPos，参数及结果: %1\n").arg(argVal), 0);

        static QTime lastTime = QTime::currentTime();
        static int callCount = 0;

        QTime now = QTime::currentTime();
        if (lastTime.msecsTo(now) < 5000) {
            callCount++;
            if (callCount > 5) {
                emit newInfo(QString::fromUtf8("警告：短时间内多次调用 GetCursorPos，可能存在鼠标行为监控！\n"), 2);
                callCount = 0;
            }
        } else {
            callCount = 1;
            lastTime = now;
        }
        break;
    }


    case SETCURSORPOS: {
        QString argX = QString::fromLatin1(recvInfo.argValue[0]);
        QString argY = QString::fromLatin1(recvInfo.argValue[1]);

        emit newInfo(QString::fromUtf8("检测到调用 SetCursorPos，参数: X=%1, Y=%2\n").arg(argX).arg(argY), 0);

        static QTime lastTime = QTime::currentTime();
        static int callCount = 0;

        QTime now = QTime::currentTime();
        if (lastTime.msecsTo(now) < 5000) {
            callCount++;
            if (callCount >=1) {
                emit newInfo(QString::fromUtf8("警告：短时间内多次调用 SetCursorPos，可能存在鼠标位置篡改风险！\n"), 2);
                callCount = 0;
            }
        } else {
            callCount = 1;
            lastTime = now;
        }
        break;
    }

    case VIRTUALFREE: {
        QString lpAddress = QString::fromLatin1(recvInfo.argValue[0]);
        QString dwSize = QString::fromLatin1(recvInfo.argValue[1]);
        QString dwFreeType = QString::fromLatin1(recvInfo.argValue[2]);

        emit newInfo(QString::fromUtf8("检测到调用 VirtualFree，参数: 地址=%1, 大小=%2, 类型=%3\n")
                         .arg(lpAddress).arg(dwSize).arg(dwFreeType), 0);

        static QTime lastTime = QTime::currentTime();
        static int callCount = 0;

        QTime now = QTime::currentTime();
        if (lastTime.msecsTo(now) < 5000) {
            callCount++;
            if (callCount > 3) {
                emit newInfo(QString::fromUtf8("警告：短时间内多次调用 VirtualFree，可能存在恶意内存操作！\n"), 2);
                callCount = 0;
            }
        } else {
            callCount = 1;
            lastTime = now;
        }
        break;
    }

    case NTREADVIRTUALMEMORY: {
        QString processHandle = QString::fromLatin1(recvInfo.argValue[0]);
        QString baseAddress = QString::fromLatin1(recvInfo.argValue[1]);
        QString bufferSize = QString::fromLatin1(recvInfo.argValue[3]);
        QString bytesRead = QString::fromLatin1(recvInfo.argValue[4]);

        emit newInfo(QString::fromUtf8("调用 NtReadVirtualMemory，目标进程句柄: %1，地址: %2，读取字节: %3\n")
                         .arg(processHandle, baseAddress, bufferSize), 1);

        // 安全警告：如果读取地址较低（如0x00400000以内），可能在扫描 PE/模块信息
        bool sizeSuspicious = bufferSize.toULongLong() > 1024 * 1024;
        if (sizeSuspicious) {
            emit newInfo(QString::fromUtf8("警告：尝试读取过大的内存区域，疑似内存扫描或注入行为！\n"), 2);
        }

        break;
    }


    default:
        break;
    }
    }

void myThread::createFileCheck() {
    unsigned dwDesiredAccess = strtoul(recvInfo.argValue[1], NULL, 16);
    char copyFileName[128] = "";
    string copyFolder;
    getFileName(recvInfo.argValue[0], copyFileName);
    getLastFolder(recvInfo.argValue[0], copyFolder);
    if (dwDesiredAccess & GENERIC_WRITE) {
        if (strstr(copyFileName, ".exe") || strstr(copyFileName, ".dll") || strstr(copyFileName, ".ocx")) {
            emit newInfo(QString(QLatin1String("warning: Modifying executable program!\n")), 2);
        }
    }
    if (dwDesiredAccess & GENERIC_READ) {
        if (strcmp(fileName, copyFileName) == 0) {
            emit newInfo(QString(QLatin1String("warning: May be trying to self-replication\n")), 2);
        }
    }
    if (folderSet.find(copyFolder) == folderSet.end()) {
        folderSet.insert(copyFolder);
    }
    if (folderSet.size() >= 2) {
        emit newInfo(QString(QLatin1String("warning: Edited files in multiple folders!\n")), 2);
    }
}
void myThread::getLastFolder(char* filePath, string & folder) {
    int index = strlen(filePath);
    // 去除文件名
    while (filePath[index - 1] != '\\') {
        index--;
    }
    // 去除斜杠
    while (filePath[index - 1] == '\\') {
        index--;
    }
    // 得到文件夹
    while (filePath[index - 1] != '\\') {
        index--;
    }
    index++;
    while (filePath[index - 1] != '\\') {
        folder.push_back(filePath[index - 1]);
        index++;
    }
}
