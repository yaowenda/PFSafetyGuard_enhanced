#include "mainwindow.h"
#include "ui_mainwindow.h"
char typeStr[128][128] = {
    "",                      // 索引0不用或者保留为空
    "MessageBoxA",          // 1 - 弹窗
    "MessageBoxW",          // 2 - 弹窗
    "WriteFile",            // 3 - 写文件
    "ReadFile",             // 4 - 读文件
    "CreateFileA",          // 5 - 打开或创建文件
    "CreateFileW",          // 6 - 打开或创建文件
    "DeleteFileA",          // 7 - 删除文件
    "DeleteFileW",          // 8 - 删除文件
    "GetFileAttributesW",   // 9 - 获取文件属性
    "GetFileSize",          // 10 - 获取文件大小
    "MoveFileW",            // 11 - 移动或重命名文件
    "MoveFileExW",          // 12 - 移动文件（支持更多选项）
    "Send",                 // 13 - 发送数据
    "SendTo",               // 14 - 发送数据到指定地址
    "WSASend",              // 15 - 发送数据
    "Recv",                 // 16 - 接收数据
    "RecvFrom",             // 17 - 接收远程数据
    "WSARecv",              // 18 - 接收数据
    "Connect",              // 19 - 建立连接
    "WSAConnect",           // 20 - 建立连接
    "gethostbyname",        // 21 - 域名解析
    "getaddrinfo",          // 22 - 域名/IP解析
    "socket",               // 23 - 创建套接字
    "closesocket",          // 24 - 关闭套接字
    "CreateProcessA",       // 25 - 创建进程（ANSI版本）
    "CreateProcessW",       // 26 - 创建进程（Unicode版本）
    "ShellExecuteW",        // 27 - 执行shell命令（Unicode版本）
    "CreateThread",         // 28 - 创建线程
    "ExitThread",           // 29 - 终止线程
    "LoadLibraryA",         // 30 - 加载动态库（ANSI版本）
    "LoadLibraryW",         // 31 - 加载动态库（Unicode版本）
    "LOADLIBRARYEXA",       // 32 - 加载动态库（扩展参数，Unicode版本）
    "GetProcAddress",       // 33 - 获取函数地址
    "VirtualAllocEx",       // 34 - 在远程进程中分配内存
    "WriteProcessMemory",   // 35 - 向远程进程写入内存
    "CreateRemoteThread",   // 36 - 在远程进程中创建线程
    "CreateWindowExA",      // 37 - 创建窗口（扩展样式，ANSI版本）
    "CreateWindowExW",      // 38 - 创建窗口（扩展样式，Unicode版本）
    "RegisterClassA",       // 39 - 注册窗口类（ANSI版本）
    "RegisterClassW",       // 40 - 注册窗口类（Unicode版本）
    "SetWindowLongA",       // 41 - 设置窗口属性（ANSI版本）
    "SetWindowLongW",       // 42 - 设置窗口属性（Unicode版本）
    "ShowWindow",           // 43 - 显示窗口
    "DestroyWindow",        // 44 - 销毁窗口
    "GetAsyncKeyState",     // 45 - 检查某个键被按下还是释放
    "GetKeyState",          // 46 - 获取指定虚拟键的状态
    "RegisterHotKey",       // 47 - 注册一个系统范围的热键
    "SetWindowsHookExA",    // 48 - 安装钩子
    "GetCursorPos",         // 49 - 获取鼠标光标坐标
    "SetCursorPos",         // 50 - 将光标移动到指定位置
    "VirtualFree",          // 51 - 释放虚拟内存
    "NtQuerySystemInformation", // 52 - 获取系统级别信息
    "NtReadVirtualMemory"   // 53 - 读取指定进程的虚拟内存
};
info recvInfo;
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
	initUI();
}

MainWindow::~MainWindow()
{
    delete ui;
}
void MainWindow::initUI() {
	//QPixmap iconaaa(":/images/images/safe.ico");
	////label->setPixmap(iconaaa);
	//ui->label_5->setPixmap(iconaaa);
	//ui->tempButton->setIcon
	//ui->label_5->setWindowIcon(QIcon(":/images/images/safe.ico"));
	//ui->infoButton->setDisabled(true);
	ui->infoButton->setIcon(QIcon(":/images/images/safe.ico"));
	connect(&threadA, SIGNAL(newInfo(QString, int)), this, SLOT(on_ThreadA_newInfo(QString, int)));
	connect(&threadA, SIGNAL(newProcessModules(QString)), this, SLOT(on_ThreadA_newProcessModules(QString)));
	connect(&threadA, SIGNAL(newProcessPriority(QString)), this, SLOT(on_ThreadA_newProcessPriority(QString)));
	connect(&threadA, SIGNAL(newProcessID(QString)), this, SLOT(on_ThreadA_newProcessID(QString)));
	connect(&threadA, SIGNAL(newProcessName(QString)), this, SLOT(on_ThreadA_newProcessName(QString)));
	//connect(&threadA, SIGNAL(newValue(QString)), this, SLOT(on_ThreadA_newValue(QString)));
	connect(&threadA, SIGNAL(newInfo()), this, SLOT(on_ThreadA_newInfo()));
}
void MainWindow::on_openFileButton_pressed() {
	QString fileName = QFileDialog::getOpenFileName(
		this, tr("open image file"),
        "D:\\PFSafetyGuard\\PFSafetyGuard\\testCode\\x64\\Release", tr("Image files(*.txt *.exe);;All files (*.*)"));

	if (fileName.isEmpty())
	{
		QMessageBox mesg;
		mesg.warning(this, "warning", "open file failed");
		return;
	}
	else
	{
		ui->filePathTextEdit->setText(fileName);
	}
}

void MainWindow::on_tempButton_pressed() {
	QByteArray temp = ui->filePathTextEdit->toPlainText().toLatin1();
	threadA.init(temp.data());
	threadA.start();
}

void MainWindow::on_clsButton_pressed() {
	ui->infoTree->clear();
    ui->filePathTextEdit->setText("");
}


void MainWindow::on_ThreadA_newValue(QString str) {
	//ui->tempLabel->setText(str);
	//ui->filePathTextEdit->setText(str);
}

void MainWindow::closeEvent(QCloseEvent *event) {
	if (threadA.isRunning()) {
		threadA.stopThread();
		threadA.wait();
	}
	event->accept();
}

void MainWindow::on_ThreadA_newInfo() {
	//QString temp = QString(QLatin1String(fileName));
	//emit newValue(QString(QLatin1String(fileName)));
	//msleep(1500);
	QTreeWidgetItem* item = new QTreeWidgetItem();
	char temp[128] = "";
	sprintf(temp, "%d-%d-%d %-02d:%-02d  (%-d.%-ds)",
		recvInfo.st.wYear, recvInfo.st.wMonth, recvInfo.st.wDay,
		recvInfo.st.wHour, recvInfo.st.wMinute, recvInfo.st.wSecond,
        recvInfo.st.wMilliseconds);

    item->setData(0, 0, QString(typeStr[recvInfo.type]));
    item->setData(1, 0, QString(temp));
    for (int i = 0; i < recvInfo.argNum; i++) {
        QTreeWidgetItem* item2 = new QTreeWidgetItem();
        item2->setData(0, 0, QString::fromLocal8Bit(recvInfo.argName[i]));
        item2->setData(1, 0, QString::fromLocal8Bit(recvInfo.argValue[i]));
        item->addChild(item2);
    }
 //    QTreeWidgetItem* item2 = new QTreeWidgetItem();
 //    item->setData(1, 0, "2222");
 //    item2->setData(0, 0, "3333");
 //    item2->setData(1, 0, "4444");
 //    item->addChild(item2);
 //    QTreeWidgetItem* item3 = new QTreeWidgetItem();
 //    item3->setData(0, 0, "5555");
 //    item3->setData(1, 0, "6666");
 //    item->addChild(item3);
    ui->infoTree->addTopLevelItem(item);
}
void MainWindow::on_ThreadA_newProcessName(QString str) {
	ui->processName->setText(str);
}
void MainWindow::on_ThreadA_newProcessID(QString str) {
	ui->processID->setText(str);
}
void MainWindow::on_ThreadA_newProcessPriority(QString str) {
	ui->processPriority->setText(str);
}
void MainWindow::on_ThreadA_newProcessModules(QString str) {
	ui->processModules->setText(str);
}
void MainWindow::on_ThreadA_newInfo(QString str, int status) {
    ui->info->append(str);
	if (status == 2) {
		ui->infoButton->setIcon(QIcon(":/images/images/error.ico"));
	}
	else if (status == 1) {
		ui->infoButton->setIcon(QIcon(":/images/images/warning.ico"));
	}
	else {
		ui->infoButton->setIcon(QIcon(":/images/images/safe.ico"));
	}
	//ui->label_5->setWindowIcon(QIcon(":/images/images/safe.ico"));
	//ui->label_5->setWindowIcon
	//ui->info->setTextColor()
}
