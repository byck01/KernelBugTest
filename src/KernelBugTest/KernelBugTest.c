#include<ntifs.h>

//控制码
#define IOCODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x910,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCODE1  CTL_CODE(FILE_DEVICE_UNKNOWN,0x911,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCODE2  CTL_CODE(FILE_DEVICE_UNKNOWN,0x912,METHOD_NEITHER,FILE_ANY_ACCESS)
#define IOCODE3  CTL_CODE(FILE_DEVICE_UNKNOWN,0x913,METHOD_NEITHER,FILE_ANY_ACCESS)


//控制码
ULONG g_IoCode = 0;

//nt模块基地址
SIZE_T NtBase;

//记录返回地址
SIZE_T retAddr;

//挂钩IopfCompleteRequest函数的地址
SIZE_T hookFunVa;

//跳过挂钩地址
SIZE_T jmpFunVa;

//IopfCompleteRequest 函数处的opcode
UCHAR IopfComBuff[5] = { 0x8b,0xff,0x55,0x8b,0xec };

//目标驱动IRP处理函数rva
ULONG IrpFunRva;

//目标驱动hook的地址
SIZE_T hookIrpFunVa;

//hook地址处的opcode
UCHAR readOpcode[5];

//目标驱动基地址
SIZE_T BugSysBase;

//目标模块名
UNICODE_STRING sysName;

//IRP
PIRP g_pIrp;

//IRP栈
PIO_STACK_LOCATION pStack;

//IRP处理函数返回的地址
SIZE_T IrpFunRetAddr;

//IRP处理函数
NTSTATUS CommonProc(PDEVICE_OBJECT objDevice, PIRP pIrp);

//挂钩目的驱动函数
VOID OnHook(SIZE_T hookAddr, ULONG MyFun);

//MyIrpFun
void MyIrpFun();

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union _UNIONA{
		LIST_ENTRY HashLinks;
		struct _SECTION{
			PVOID SectionPointer;
			ULONG CheckSum;
		}SECTION;
	}UNIONA;
	union _UNIONB{
		struct _TIMEDATE{
			ULONG TimeDateStamp;
		}TIMEDATE;
		struct _LOADEDIMP{
			PVOID LoadedImports;
		}LOADEDIMP;
	}UNIONB;
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//卸载函数
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);

	KdPrint(("Bye"));
}

//枚举驱动
ULONG EnumDriver(PDRIVER_OBJECT pDriver, UNICODE_STRING changeSys)
{
	if (pDriver == NULL)
	{
		return 0;
	}

	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY firstentry;
	firstentry = pLdr;

	do
	{
		if (pLdr->FullDllName.Buffer != 0)
		{
			pLdr = (PLDR_DATA_TABLE_ENTRY)pLdr->InLoadOrderLinks.Blink;

		}
		//找到目标驱动
		if (!RtlCompareUnicodeString(&changeSys, &pLdr->BaseDllName, TRUE))
		{
			return pLdr->DllBase;
		}

	} while (pLdr->InLoadOrderLinks.Blink != firstentry);

	return 0;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pPath)
{
	UNREFERENCED_PARAMETER(pPath);

	DbgBreakPoint();

	//创建一个设备
	NTSTATUS status = 0;
	//设备的名字
	UNICODE_STRING pDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Byck01");

	//符号名字
	UNICODE_STRING pSysName = RTL_CONSTANT_STRING(L"\\DosDevices\\ck01");

	PDEVICE_OBJECT pDevice = NULL;



	//创建设备
	status = IoCreateDevice(pDriver, 0, &pDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevice);

	if (NT_SUCCESS(status) == FALSE)
	{
		return status;
	}

	//创建符号链接
	IoCreateSymbolicLink(&pSysName, &pDeviceName);

	//填写IRP处理函数
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = CommonProc;
	}

	UNICODE_STRING changeSys = RTL_CONSTANT_STRING(L"ntoskrnl.exe");

	//获取nt模块地址
	NtBase = EnumDriver(pDriver, changeSys);

	//卸载函数
	pDriver->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

//关闭页保护
void OffProtect()
{
	_asm
	{
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
	}
}

//开启页保护
void OnProtrect()
{
	_asm
	{
		push eax;
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		pop eax;
	}
}

//过滤信息
void FilterInformation(int flag)
{

	if (!flag)
	{
		//打印需要的信息
		KdPrint(("g_IoCode:%x\n", g_IoCode));
		KdPrint(("retAddr:%x\n", retAddr));
		KdPrint(("BugSysBase:%x\n", BugSysBase));
		KdPrint(("retAddr Rva:%x\n", retAddr - BugSysBase));
	}
	else
	{
		KdPrint(("*************Hook Information***************\n"));
		KdPrint(("Hook IopfCompleteRequest Addr:%x\n", hookFunVa));
		KdPrint(("Hook Irp Function Addr:%x\n", hookIrpFunVa));

		//打印IRP栈上的信息
		KdPrint(("*************Send Information***************\n"));
		KdPrint(("IoControlCode:%x\n", pStack->Parameters.DeviceIoControl.IoControlCode));

		//METHOD_IN_DIRECT,METHOD_out_DIRECT,METHOD_BUFFERED方式传入的buf都是g_pIrp->AssociatedIrp.SystemBuffer
		//打印下地址
		KdPrint(("Input SystemBuffer:%x\n", g_pIrp->AssociatedIrp.SystemBuffer));
		//METHOD_NEITHER 方式传入的buf是pStack->Parameters.DeviceIoControl.Type3InputBuffer
		KdPrint(("Type3InputBuffer:%x\n", pStack->Parameters.DeviceIoControl.Type3InputBuffer));

		//打印inputBufferSize
		KdPrint(("InputBufferSize:%x\n", pStack->Parameters.DeviceIoControl.InputBufferLength));

		//METHOD_IN_DIRECT,METHOD_out_DIRECT方式的传出buf：irp->MdlAddress
		KdPrint(("MdlAddress:%x\n", g_pIrp->MdlAddress));

		//METHOD_BUFFERED 方式传出buf: irp->AssociatedIrp.SystemBuffer
		KdPrint(("Output SystemBuffer:%x\n", g_pIrp->AssociatedIrp.SystemBuffer));

		//METHOD_NEITHER  方式传出buf:irp->UserBuffer
		KdPrint(("UserBuffer:%x\n", g_pIrp->UserBuffer));

		//打印OutputBufferSize
		KdPrint(("OutputBufferSize:%x\n", pStack->Parameters.DeviceIoControl.InputBufferLength));


		//恢复原来的指令
		OffProtect();
		memcpy(hookIrpFunVa, readOpcode, 0x5);
		OnProtrect();
	}


}

//MyIopfCompleteRequest
_declspec(naked) void MyIopfCompleteRequest()
{
	_asm
	{
		mov eax, dword ptr[esp];//记录返回地址
		mov retAddr, eax;
		mov eax, ecx;//获取IRP
		mov eax, dword ptr[eax + 0x60];//获取IRP栈
		mov eax, dword ptr[eax + 0xc];//获取IoControlCode
		cmp eax, g_IoCode;//判断是不是目标的控制码
		jnz j_End;
		pushad;
		push 0;
		call FilterInformation;
		popad;
	j_End:
		mov edi, edi;
		push ebp;
		mov ebp, esp;
		jmp jmpFunVa; //跳转执行原来指令
	}
}

//重新挂钩
_declspec(naked)retHookA()
{
	_asm
	{
		int 0x3;
		pushad;
		push MyIrpFun;
		push hookIrpFunVa;
		call OnHook;
		popad;
		jmp IrpFunRetAddr; //跳回原来返回执行的地方
	}
}

//MyIrpFun
_declspec(naked) void MyIrpFun()
{
	_asm
	{
		int 0x3;
		mov eax, dword ptr[esp];//记录IRP处理函数的返回地址
		mov IrpFunRetAddr, eax;

		mov eax, dword ptr[esp + 0x8];//IRP
		mov g_pIrp, eax;

		mov eax, dword ptr[eax + 0x60];//IRP栈
		mov pStack, eax;//保存IRP栈地址

		pushad;
		push 0x1;
		call FilterInformation;
		popad;

		mov eax, retHookA;
		mov dword ptr[esp], eax;//修改返回地址

		jmp hookIrpFunVa;
	}
}


//jmp opcode
UCHAR NewCodeBuf[5] = { 0xE9 };
//挂钩目的驱动函数
VOID OnHook(SIZE_T hookAddr, ULONG MyFun)
{

	//关闭页保护
	OffProtect();

	//要跳转到函数执行
	*(ULONG *)(NewCodeBuf + 1) = (ULONG)MyFun - (ULONG)hookAddr - 5;

	memcpy(hookAddr, NewCodeBuf, 5);

	//开启页保护
	OnProtrect();
}

//IRP处理函数
NTSTATUS CommonProc(PDEVICE_OBJECT objDevice, PIRP pIrp)
{
	//根据请求的方法判断处理
	//获取IRP栈
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	ANSI_STRING ansiString;

	switch (pStack->MajorFunction)
	{
	case IRP_MJ_READ:
		break;
	case IRP_MJ_DEVICE_CONTROL:
	{
		//根据IOCtrl码处理
		switch (pStack->Parameters.DeviceIoControl.IoControlCode)
		{//挂钩IopfCompleteRequest
		case IOCODE:
		{
			if (pStack->Parameters.DeviceIoControl.Type3InputBuffer == NULL)
			{
				KdPrint(("Buffer is NULL\n"));
				break;
			}

			//获取目标控制码
			g_IoCode = *((ULONG *)pStack->Parameters.DeviceIoControl.Type3InputBuffer);
			KdPrint(("g_IoCode:%x\n", g_IoCode));

			//挂钩IopfCompleteRequest
			if (!NtBase)
			{
				break;
			}

			//挂钩函数地址
			hookFunVa = NtBase + 0x78809;

			//跳转地址
			jmpFunVa = hookFunVa + 0x5;

			OnHook(hookFunVa, MyIopfCompleteRequest);
			break;
		}//获取目标模块基地址
		case IOCODE1:
		{
			if (pStack->Parameters.DeviceIoControl.Type3InputBuffer == NULL)
			{
				KdPrint(("Buffer is NULL\n"));
				break;
			}

			//获取目标模块名
			ansiString.Buffer = pStack->Parameters.DeviceIoControl.Type3InputBuffer;
			ansiString.Length = ansiString.MaximumLength = pStack->Parameters.DeviceIoControl.InputBufferLength;

			RtlAnsiStringToUnicodeString(&sysName, &ansiString, TRUE);
			DbgBreakPoint();
			//获取目标驱动基地址
			BugSysBase = EnumDriver(objDevice->DriverObject, sysName);
			KdPrint(("BugSysBase:%x\n", BugSysBase));
			DbgBreakPoint();
			break;
		}//hook目标驱动的IRP处理函数
		case IOCODE2:
		{
			if (pStack->Parameters.DeviceIoControl.Type3InputBuffer == NULL || BugSysBase == 0)
			{
				KdPrint(("Buffer Or BugSysBase is NULL\n"));
				break;
			}

			//获取目标驱动IRP处理函数的rva
			IrpFunRva = *((ULONG *)pStack->Parameters.DeviceIoControl.Type3InputBuffer);

			//计算VA
			hookIrpFunVa = BugSysBase + IrpFunRva;

			//读取buf里
			RtlCopyMemory(readOpcode, (UCHAR *)hookIrpFunVa, 0x5);

			//hook对应函数
			OnHook(hookIrpFunVa, MyIrpFun);
			break;
		}//清除hook点
		case IOCODE3:
		{
			if (hookIrpFunVa != 0)
			{
				//恢复原来的指令
				OffProtect();
				memcpy(hookIrpFunVa, readOpcode, 0x5);
				OnProtrect();
			}

			if (hookFunVa != 0)
			{
				//恢复原来的指令
				OffProtect();
				memcpy(hookFunVa, IopfComBuff, 0x5);
				OnProtrect();
			}
			break;
		}
		default:
			break;
		}

	}
	default:
		break;
	}
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}