// 测试学习.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
 #include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include<TlHelp32.h>
#include<string.h>
#include"FileName.h"
#include"crc32.h"
#include <opencv2/opencv.hpp>
// 反调试学习
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    DWORD PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger
}THREAD_INFO_CLASS;

typedef NTSTATUS(NTAPI* _ZwSetInformationThread)(
    HANDLE          ThreadHandle,
    THREAD_INFO_CLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
    );

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation  // 所有对象类型信息
} OBJECT_INFORMATION_CLASS;

 typedef NTSTATUS (NTAPI *_NtQueryObject)(
     HANDLE                   Handle,
     OBJECT_INFORMATION_CLASS ObjectInformationClass, // 查询对象类型枚举值
     PVOID                    ObjectInformation,      // 输出结果缓冲区
     ULONG                    ObjectInformationLength,// 缓冲区大小
     PULONG                   ReturnLength             // 实际使用大小
);

 typedef struct _UNICODE_STRING
 {
     USHORT Length;
     USHORT MaximumLength;
     _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
 } UNICODE_STRING, * PUNICODE_STRING;


 /**
 * The OBJECT_NAME_INFORMATION structure contains various statistics and properties about an object type.
 */
 typedef struct _OBJECT_TYPE_INFORMATION
 {
     UNICODE_STRING TypeName; // 内核对象类型名称
     ULONG TotalNumberOfObjects;
     ULONG TotalNumberOfHandles;
     ULONG TotalPagedPoolUsage;
     ULONG TotalNonPagedPoolUsage;
     ULONG TotalNamePoolUsage;
     ULONG TotalHandleTableUsage;
     ULONG HighWaterNumberOfObjects;
     ULONG HighWaterNumberOfHandles;
     ULONG HighWaterPagedPoolUsage;
     ULONG HighWaterNonPagedPoolUsage;
     ULONG HighWaterNamePoolUsage;
     ULONG HighWaterHandleTableUsage;
     ULONG InvalidAttributes;
     GENERIC_MAPPING GenericMapping;
     ULONG ValidAccessMask;
     BOOLEAN SecurityRequired;
     BOOLEAN MaintainHandleCount;
     UCHAR TypeIndex; // since WINBLUE
     CHAR ReservedByte;
     ULONG PoolType;
     ULONG DefaultPagedPoolCharge;
     ULONG DefaultNonPagedPoolCharge;
 } OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

 typedef struct  _OBJECT_TYPES_INFORMATION
 {
    ULONG numberOfTypesInfo;
    OBJECT_TYPE_INFORMATION typeInfo[1];
 }OBJECT_TYPES_INFORMATION,*POBJECT_TYPES_INFORMATION;

EXCEPTION_DISPOSITION WINAPI SEH_myExceptHandler(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    PVOID EstablisherFrame,
    PCONTEXT pcontext,
    PVOID DispatcherContext
) {

    if (pcontext->Dr0 != 0 || pcontext->Dr1 != 0 || pcontext->Dr2 != 0 || pcontext->Dr3 != 0) {
        printf("检测到硬件断点 程序被调试了1\n");
        ExitProcess(0);
    }
    printf("未检测硬件断点\n");
    // ExceptionContinueSearch 我处理不了，你继续往下执行只可以处理异常的
    // ExceptionContinueExecution 继续到异常触发的位置接着执行

#ifndef _WIN64

#else
      //pcontext->Eip = pcontext->Eip + 2;
#endif
    return ExceptionContinueExecution;
}

//unsigned make_crc(const unsigned char* instr, const size_t& strlent) {
//    // 这里是crc32 计算，还没写，先忽略，
//    return 0;
//}
using FnAddVectoredExceptionHandler =  PVOID(NTAPI* )(ULONG, _EXCEPTION_POINTERS*);

LONG NTAPI VEH_VectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{
#ifndef WIN32
    MessageBox(NULL, L"VEH异常处理函数执行了...", L"VEH异常", MB_OK);
#endif
    
    if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xC0000094)//除0异常
    {
#ifndef _WIN64

#else
        //将除数修改为1
        //pExcepInfo->ContextRecord->Ecx = 1;

        //修改发生异常的代码的Eip    idiv ecx长度2字节 从下一行开始执行
        //pExcepInfo->ContextRecord->Eip = pExcepInfo->ContextRecord->Eip + 2;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;//异常已处理
    }
    else if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000008) {
        // CloseHandle 关闭了一个不存在的句柄 内核就会触发异常
        return EXCEPTION_CONTINUE_SEARCH;//异常未处理
    }
    else if (pExcepInfo->ExceptionRecord->ExceptionCode ==  0xc0000096) {
        // 这里异常是？虚拟机检测的异常
#ifndef _WIN64

#else
        //pExcepInfo->ContextRecord->Eip = pExcepInfo->ContextRecord->Eip + 1;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;//异常已处理
    }
    else {
        // 获取异常对象指针
        std::cout << std::hex << pExcepInfo->ExceptionRecord->ExceptionCode << std::endl;
        //ULONG_PTR pExceptionObject = pExcepInfo->ExceptionRecord->ExceptionInformation[1];
        //// 将异常对象转换为 std::exception 指针
        //std::exception* pException = (std::exception * ) (pExceptionObject);
        //// 获取异常信息
        //std::cerr << "C++ 异常: " << pException->what() << std::endl;
    }

    return EXCEPTION_CONTINUE_SEARCH;//异常未处理
}

DWORD g_InitalizeFunAddr;
BYTE IninializeFun[5] = { 0 };


DWORD WINAPI threadProc(LPVOID lparam) {
    while (true) {
        DWORD newcode = *(DWORD*)g_InitalizeFunAddr;
        if (newcode  != *(DWORD*)IninializeFun) {
            std::cout << "这孙子要附加进程" << std::endl;

            // 把内存改回去
            DWORD oldProtect = 0;
            VirtualProtect(
                (LPVOID)g_InitalizeFunAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy((LPVOID)g_InitalizeFunAddr, IninializeFun, 5);
            VirtualProtect(
                (LPVOID)g_InitalizeFunAddr, 5, oldProtect, &oldProtect);
        }
    }
}
BOOL SaveLdrInitializeCode()
{
    DWORD functadd = (DWORD)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrInitializeThunk");
    g_InitalizeFunAddr = functadd;
    memcpy(IninializeFun, (void*)g_InitalizeFunAddr, 5);
    return true;
}
// 
BOOL hookdbgBreakPoint() {

    BYTE* functadd = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint");
    // 把内存改回去
    DWORD oldProtect = 0;
    VirtualProtect(
        (LPVOID)functadd, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    // memcpy((LPVOID)g_InitalizeFunAddr, IninializeFun, 5);
    functadd[0] = 0xc3;

    VirtualProtect(
        (LPVOID)functadd, 5, oldProtect, &oldProtect);

    return true;
}

BOOL checkvm() {
    // 这段只有虚拟机会异常，会调用上面的 VEH_VectExcepHandler 函数
#ifndef WIN32
    __try {
        __asm {
            push edx
            push ecx
            push ebx
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            in eax, dx
            //cmp ebx, 'VMXh'
            pop ebx
            pop ecx
            pop edx
        }
    }
    __except (1) {
        return true;
    }
#endif
    return false;
    
}

BOOL checkDbgWindow() {
#ifndef WIN32
    HWND hwnd = FindWindow(NULL, L"x3dbg");
    if (hwnd) {
        std::cout << "检测到x32dbg调试器" << std::endl;
        return true;
    }
#endif
    return false;
}

void m_Exitprocess() {
    std::cout << "检测到单步调试器" << std::endl;
    ExitProcess(0);
}

void checkTFflag() {
    // 单步执行这里 就会终止进程
    DWORD addt = (DWORD)m_Exitprocess;
#ifndef WIN32
    __try {
        __asm {
            pushfd
            or dword ptr ss : [esp] , 0x100
            popfd
            nop
            jmp addt
        }
    }
    __except (1) {
        std::cout << "没有检测到单步调试器" << std::endl;
    }
#endif
}
BOOL CALLBACK EnumChildProc(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
) {
    wchar_t str[0x100] = { 0 };
    // MultiByteToWideChar 窄字节转宽字节
    // WideCharToMultiByte 宽字节转窄字节
#ifndef WIN32
    SendMessage(hwnd, WM_GETTEXT, 0x100, (LPARAM)str);
    // printf("窗口名称是：%s\n", str);
    if (str != L"") {
        std::wcout << "窗口名称是: " << str ;
    }
#endif
    return true;
}

typedef int (*funPtr)(int);

int add(int) {
    return 0;
}

int add(int, int) {
    return 0;
}


#define Max 10


int add(int, int,int) {
    return 0;
}

int main()
{
	cv::Mat image = cv::imread("./tupian1.jpg");
    cv::Mat image2 = cv::imread("./tupian2.jpg");
	cv::namedWindow("image", cv::WINDOW_NORMAL);  // 创建一个可调整大小的窗口
    
    cv::Mat outmat;
    if (image.rows == image2.rows && image.cols == image2.cols)
    {
        cv::addWeighted(image, 0.5, image2, 0.5, 3, outmat);
        cv::imshow("image", outmat);
    }
    
	cv::waitKey(0);
    void (*func_ptr1)(int);
    auto a_lambda_func = [](int x) { /*...*/ };

    void (*func_ptr)(int) = a_lambda_func;
    func_ptr(1);
    
    

    
    int test[10] = { 0 };
    int  bds = 20;

    printf("%p\n", &test);
    printf("%p\n", &bds);
    //printf("%d\n", &bds - &test);
    int* sdfdsf = ((&bds)   )+1;
    
    int* ssd = (int*)sdfdsf;
    printf("%d", *ssd);
    
    
    
    return 0;
    //int retval = 0;
    //char driverNames[][20] = { "usbfs","hub" };
    //size_t totalDrivers = sizeof(driverNames) / sizeof(driverNames[0]);
    //std::cout << totalDrivers << std::endl;
    //for (int i = 0; i < totalDrivers; i++) {
    //    std::cout << driverNames[i] << std::endl;
    //    if (strcmp("xxx", driverNames[i]) != 0) {
    //        // return retval;
    //    }
    //    else {
    //        /*pr_info("%s: registered new interface driver %s\n",
    //            usbcore_name, new_driver->name);*/
    //    }
    //}
    //return retval;
    // CreateFileW(
    /*_In_ LPCWSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        );*/
    // CreateFileA(
    /*_In_ LPCSTR lpFileName,
        _In_ DWORD dwDesiredAccess,
        _In_ DWORD dwShareMode,
        _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        _In_ DWORD dwCreationDisposition,
        _In_ DWORD dwFlagsAndAttributes,
        _In_opt_ HANDLE hTemplateFile
        );*/
    HANDLE handle = CreateFile(L"\\\\.\\52hook", GENERIC_ALL, 0, NULL, OPEN_EXISTING , FILE_ATTRIBUTE_SYSTEM, 0);
    if (handle) {
        printf("打开成功\n");
        const char* devices_sendstr = "Hello 51hook";
        DWORD realWrite = 0;
        WriteFile(handle, devices_sendstr, strlen(devices_sendstr) + 1, &realWrite, NULL);
        

        CloseHandle(handle);
    }
    else {
        printf("打开失败\n");
    }
    

    // test(); // 测试自定义节里面的函数指针变量
    _ZwSetInformationThread ZwSetInformationThread;
    _NtQueryInformationProcess NtQueryInformationProcess;
    _NtQueryObject NtQueryObject;
    FnAddVectoredExceptionHandler MyAddVectoredExceptionHandler;
    //PROCESSINFOCLASS
    // LPDEBUG_EVENT out_debuevent;
    //DWORD testst;
    //WaitForDebugEvent(out_debuevent, 0);
    // 注册sehandler
    DWORD sehHandler = (DWORD)SEH_myExceptHandler;
    // 参考 https://blog.csdn.net/qq_38474570/article/details/104346421 
    // 异常来获取进程上下文信息里面包含了寄存器信息，
    //  KiUserExceptionDispatcher会调用RtlDispatchException函数来查找并调用异常处理函数，查找的顺序：
    // 先查全局链表：VEH
    // 再查局部链表：SEH
    // veh 实现
    HMODULE Kerne_hModule = GetModuleHandle(L"Kernel32.dll");
     MyAddVectoredExceptionHandler = (FnAddVectoredExceptionHandler)::GetProcAddress(Kerne_hModule, "AddVectoredExceptionHandler");
     //参数1表示插入VEH链的头部, 0插入到VEH链的尾部
      MyAddVectoredExceptionHandler(0, (_EXCEPTION_POINTERS*)&VEH_VectExcepHandler);
     //throw("abcds");
    // seh 实现的
    /*__asm {
        push sehHandler
        mov eax, fs:[0]
        push eax
        mov fs:[0],esp
    }*/
    
    // 构造除0异常
#ifndef WIN32
     __asm
    {
        xor edx, edx
        xor ecx, ecx
        mov eax, 0x10
        idiv ecx // EDX:EAX 除以 ECX
    }
#endif
     // throw("x");  //抛出异常 myExceptHandler 函数就会被执行
      // 解绑异常
      /*__asm {
          mov eax,[esp]
          mov fs:[0],eax
          add esp,8
      }*/
    DWORD isbug = 0;
    BOOL isdebug = IsDebuggerPresent();
    if (isdebug) {
        printf("IsDebuggerPresent检测到 被调试\n");
    }
    else {
        printf("IsDebuggerPresent未被调试\n");
    }

#ifndef WIN32
    _asm {
        mov eax, fs: [0x30]
        mov eax, [eax + 0x68]
        mov isbug, eax
    }
#endif
    if (isbug == 0x70) {
        // 以附件的形式 无法检测到
        printf("NtglobalFlag标致检测到 被调试\n");
    }
    else {
        // vs debug调试检测不到
        printf("NtglobalFlag标致 未被调试\n");
    }

    // ProcessDebugPort 调试端口  7
    // ProcessDebugObject 调试对象的句柄30
    // ProcessDebugFlags 31  0调试状态 1 非调试状态
    BOOL pbDebuggerPresent = false;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &pbDebuggerPresent);

    if (pbDebuggerPresent) {
        printf("ProcessDebugPort 端口 被调试\n");
    }
    else {
        printf("ProcessDebugPort 端口 未被调试\n");
    }


    HMODULE hmodule = LoadLibraryA("ntdll.dll");
    //GetModuleHandleA("ntdll.dll");  // 这种也可以获取 dll 对象
    if (hmodule != 0) {
        NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hmodule, "NtQueryInformationProcess");
        ZwSetInformationThread = (_ZwSetInformationThread)GetProcAddress(hmodule, "ZwSetInformationThread");
        NtQueryObject = (_NtQueryObject)GetProcAddress(hmodule, "NtQueryObject");
    }
    //


    DWORD debugPort = 0;
    HANDLE DebugHandle = 0;
    BOOL ProcessDebugFlags = false;
    NtQueryInformationProcess(GetCurrentProcess(), 7, &debugPort, sizeof(DWORD), NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 30, &DebugHandle, sizeof(HANDLE), NULL);
    NtQueryInformationProcess(GetCurrentProcess(), 31, &ProcessDebugFlags, sizeof(BOOL), NULL);


    if (debugPort != 0) {
        printf("ProcessDebugPort 调试状态\n");
    }
    else {
        printf("NtQueryInformationProcess 未被调试\n");
    }

    if (DebugHandle != 0) {
        printf("ProcessDebugObject 调试状态\n");
    }
    else {
        printf("ProcessDebugObject 未被调试\n");
    }

    if (ProcessDebugFlags == 0) {
        printf("ProcessDebugFlags 检测到调试器\n");
    }
    else {
        printf("ProcessDebugFlags 未被调试\n");
    }
    
    try {
        // 关闭一个不存在的句柄 如果被调试 就会触发异常
        // vs debug时会抛出异常，用户正常运行时 不会有异常问题
        CloseHandle((HANDLE)0x112121);
    }
    catch (std::exception e) {
        printf("CloseHandle 检测到被调试\n");
    }

    // 设置线程信息分离调试器  如果遇到调试将会自动退出剥离调试线程
    ZwSetInformationThread(GetCurrentProcess(), ThreadHideFromDebugger, NULL, NULL);


    // 硬件断点 检测
    CONTEXT context{ 0 };
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentProcess(), &context);

    if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
        printf("检测到硬件断点 程序被调试了\n");
    }
    else {
        printf("未检测到硬件断点\n");
    }

    // 获取父进程Handle
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    ULONG returnlength;
    NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &basicInfo, sizeof(PROCESS_BASIC_INFORMATION), &returnlength);

    // 获取资源管理器Handler
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("创建进程快照失败\n");
    }
    PROCESSENTRY32 lpprocessentry;
    lpprocessentry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap, &lpprocessentry);
    do {
        if (wcscmp(L"explorer.exe", lpprocessentry.szExeFile) == 0) {
            if (lpprocessentry.th32ProcessID != basicInfo.InheritedFromUniqueProcessId) {
                printf("程序可能被调试了\n");
            }

        }
        else if(wcscmp(L"vmtoolsd.exe", lpprocessentry.szExeFile) == 0){
            // 虚拟机进程
            printf("程序在虚拟机中运行\n");
        }
        else if (wcscmp(L"x32dbg.exe", lpprocessentry.szExeFile) == 0) {
            // x32dbg 调试工具
            printf("检测到 x32dbg 调试工具\n");
        }
    } while (Process32Next(hSnap, &lpprocessentry));
    if (hSnap != 0) {
        CloseHandle(hSnap);
    }


    //
    char* charbuffer = (char*)malloc(0x4000);
    DWORD realsiez = 0;
    NTSTATUS ret = NtQueryObject(NULL, ObjectTypesInformation, charbuffer, 0x4000, &realsiez);

    if (ret != 0)
    {
        printf("NtQueryObject error");
    }
    POBJECT_TYPES_INFORMATION typesInfo = (POBJECT_TYPES_INFORMATION) (charbuffer);
    POBJECT_TYPE_INFORMATION typeinfo = typesInfo->typeInfo;
    for (ULONG i = 0; i < typesInfo->numberOfTypesInfo; i++) {
        if (wcscmp(L"DebugObject", typeinfo->TypeName.Buffer) == 0) {
            if (typeinfo->TotalNumberOfObjects > 0) {
                printf("调试对象数量：%d ", typeinfo->TotalNumberOfObjects);
                printf("检测到调试对象\n");
                break;
            }
            else {
                printf("未检测到调试对象\n");
            }
        }
#ifndef WIN32
        DWORD buffLen = typeinfo->TypeName.MaximumLength;
        buffLen = buffLen + buffLen % 4;
        typeinfo = (POBJECT_TYPE_INFORMATION)((DWORD)typeinfo + buffLen);
        typeinfo++;
        

        // debug 模式下会出现cdcdcdc情况
        char* temp = (char*)typeinfo->TypeName.Buffer;
        temp = temp + typeInfo->Typename.MaximumLength;
        temp = temp + (DWORD)temp % 4;
        DWORD data = *(DWORLD*)temp;
        while (data == 0) {
            temp += 4;
            data = *(DWORD*)temp;
        }
        typeinfo = (POBJECT_TYPE_INFORMATION)temp;
#endif
    }

    // 
    free(charbuffer);

#ifndef WIN32
    // crc32 判断int3断点
    
    char*  buff = (char*)GetModuleHandleA(0); // 获取模块的首地址

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff; // 转换为dos 头
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + buff);
    
    PIMAGE_SECTION_HEADER pfirstHeader = ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(pNtHeader)+((LONG)__builtin_offsetof(IMAGE_NT_HEADERS, OptionalHeader)) + ((pNtHeader))->FileHeader.SizeOfOptionalHeader));
    
    int selectnum = pNtHeader->FileHeader.NumberOfSections; // 获取节的数量
    
    for (int i = 0; i < selectnum; i++) {
        if (pfirstHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            // 有执行权限
            uint32_t crc111 = make_crc((unsigned char*)(pfirstHeader->VirtualAddress + buff), pfirstHeader->Misc.VirtualSize);
            std::cout << "有执行 权限名称是：" << pfirstHeader->Name << " 0x" << std::hex << crc111 << std::endl;

        }
        else {
            std::cout << "没有执行权限，名称是：" << pfirstHeader->Name << std::endl;
        }
        pfirstHeader++;
    }
    // vmware 检测
    // 1 遍历进程快照判断有没有 vmtoolsd.exe 进程 "VBoxService.exe", "VBoxTray.exe", "vmware.exe", "vmtoolsd.exe" 
    // 2 判断 文件是否存在 C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe
    // 3 判断系统服务 有没有
    // 4 其它很多方式
    // 更多vmware 检测参考 https://github.com/ZanderChang/anti-sandbox
    // 遍历系统服务
    // 参考 https://github.com/enginestein/Virus-Collection/tree/main/Others/nesebot1.2/net.cpp#L196-L247
    // 查询服务 需要已管理员运行
    SC_HANDLE hSchandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    DWORD bytesNeeded = 0, servicesreturned, resumehandle = 0;
    // 第一次调用 EnumServicesStatusW 以获取所需的缓冲区大小
    EnumServicesStatus(hSchandle, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesreturned, &resumehandle);
    if (GetLastError() != ERROR_MORE_DATA && bytesNeeded <= 0) {
        return 0;
    }
    
        LPENUM_SERVICE_STATUS pPssp = (LPENUM_SERVICE_STATUS)malloc(bytesNeeded);
    ZeroMemory(pPssp, bytesNeeded);
    // 第二次调用 EnumServicesStatusW 以获取服务信息
    EnumServicesStatus(hSchandle, SERVICE_WIN32, SERVICE_STATE_ALL, 
        pPssp, bytesNeeded, &bytesNeeded,
        &servicesreturned, &resumehandle);

    for (int i = 0; i < (int)servicesreturned; i++) {

        switch (pPssp[i].ServiceStatus.dwCurrentState) {
            case SERVICE_STOPPED:
                //sprintf(svcState, "    Stopped");
                break;
            case SERVICE_START_PENDING:
                //sprintf(svcState, "   Starting");
                break;
            case SERVICE_STOP_PENDING:
                // sprintf(svcState, "    Stoping");
                break;
            case SERVICE_RUNNING:
                //sprintf(svcState, "    Running");
                break;
            case SERVICE_CONTINUE_PENDING:
                //sprintf(svcState, " Continuing");
                break;
            case SERVICE_PAUSE_PENDING:
                //sprintf(svcState, "    Pausing");
                break;
            case SERVICE_PAUSED:
                //sprintf(svcState, "     Paused");
                break;
            default:
                //sprintf(svcState, "    Unknown");
                break;
        }
        // std::wcout << pPssp[i].lpDisplayName << "------------ " << pPssp[i].lpServiceName << std::endl;
          std::string vmstr = "VMware";
         //std::wcout << pPssp[i].lpDisplayName << "------------ " << pPssp[i].lpServiceName << std::endl;
        std::wstring vmwarestr = std::wstring(vmstr.begin(), vmstr.end());
        if (wcsstr(pPssp[i].lpDisplayName, vmwarestr.c_str()) != 0) {
            // std::wcout << pPssp[i].lpDisplayName  << std::endl;
            printf("检测到虚拟机服务\n");
            break;
        }

    }
#endif

#ifndef WIN32
    // 关闭服务句柄
    CloseServiceHandle(hSchandle);
#endif
    std::cout << " dao zheli" << std::endl;
    checkvm();
   
    
    //  附加调试打开进程，已经附加了，后面就不能有其它调试器附加了

    // strong od 反反附加
    SaveLdrInitializeCode();
    hookdbgBreakPoint();

    // 单步调试检测
    checkTFflag();
#ifndef WIN32
    //获取桌面窗口所有的子窗户，获取所有的标题，包括浏览器标题
    HWND dDesktop = GetDesktopWindow();
    HWND deskSubwindow = GetWindow(dDesktop, GW_CHILD);
    while (deskSubwindow) {
        // char str[0x100] = { 0 };
        // GetWindowText(deskSubwindow, (LPWSTR)str, 0x100);
        EnumChildWindows(deskSubwindow, EnumChildProc, NULL);
        deskSubwindow =  GetWindow(deskSubwindow, GW_HWNDNEXT);
        
    }
#endif


    // 创建线程
    // HANDLE hThread = CreateThread(NULL, 0, threadProc, 0, 0, NULL);

    /*while (true) {
        std::cout << "xxxxxxd" << std::endl;
        Sleep(3000);
    }*/

    system("pause");
    return 0;
}

