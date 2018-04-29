#include<windows.h>
#include"getopt.h"
#include<stdio.h>
#include<stdlib.h>

//控制码
//挂钩IopfCompleteRequest
#define IOCODE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x910,METHOD_NEITHER,FILE_ANY_ACCESS)

//获取目标模块基地址
#define IOCODE1  CTL_CODE(FILE_DEVICE_UNKNOWN,0x911,METHOD_NEITHER,FILE_ANY_ACCESS)

//挂钩IRP处理函数
#define IOCODE2  CTL_CODE(FILE_DEVICE_UNKNOWN,0x912,METHOD_NEITHER,FILE_ANY_ACCESS)

//恢复指令
#define IOCODE3  CTL_CODE(FILE_DEVICE_UNKNOWN,0x913,METHOD_NEITHER,FILE_ANY_ACCESS)

DWORD parseHex(char *str) {
	DWORD value = 0;

	for (;; ++str) {
		switch (*str) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			value = value << 4 | *str & 0xf;
			break;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			value = value << 4 | 9 + *str & 0xf;
			break;
		default:
			return value;
		}
	}
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	int ret;
	//打开设备符号句柄、
	BOOL Ioret = FALSE;
	DWORD retLen;
	HANDLE hDevice = CreateFileW(L"\\\\.\\ck01", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	char *cBugSysName = NULL;
	DWORD ioCode;
	char *pIoCode;
	char IoCodeBuff[4] = { 0 };
	DWORD rva;
	char *pRva;
	char IrpFunRvaBuff[4] = { 0 };
	int j = 0;
	int inputlen;


	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return -1;
	}
	else
	{
		printf("Open Ok\n");
	}

	while ((ret = getopt(argc, argv, "n:i:r:dh")) != -1)
	{
		switch (ret) {
		case 'n':
		{
			cBugSysName = optarg;
			inputlen = strlen(optarg) *sizeof(char);
			j += 1;
			break;
		}
		case 'i':
		{
			pIoCode = optarg;
			ioCode = (DWORD)parseHex(pIoCode);
			*((int *)IoCodeBuff) = ioCode;
			j += 2;
			break;
		}
		case 'r':
		{
			pRva = optarg;
			rva = (DWORD)parseHex(pRva);
			*((int *)IrpFunRvaBuff) = rva;
			j += 4;
			break;
		}
		case 'd':
		{
			//发送目标模块名
			Ioret = DeviceIoControl(hDevice, IOCODE3, NULL, NULL, NULL, NULL, &retLen, 0);
			if (!Ioret)
			{
				printf("Send Io error\n");
				return -1;
			}
			else
			{
				printf("Send Io Ok\n");
			}
			break;
		}
		case 'h':
		default:
		{
			printf("Usage:\n");
			printf("+Get IRP processing function: KernelBugRing3 -n DriverName -i IoControlCode\n");
			printf("++Hook IRP handler: KernelBugRing3 -r IrpFunction Rva\n");
			printf("+If you already know the IRP handler, you can hook it directly: KernelBugRing3 -n DriverName -r IrpFunction Rva\n");
			printf("+Recovery instruction:KernelBugRing3 -d\n");
			break;
		}
		
		}
	}

	if (j == 3)
	{
		//发送目标模块名
		Ioret = DeviceIoControl(hDevice, IOCODE1, cBugSysName, inputlen, NULL, NULL, &retLen, 0);
		if (!Ioret)
		{
			printf("Send Io error\n");
			return -1;
		}
		else
		{
			printf("cBugSysName:%s inputlen:%d\n",cBugSysName,inputlen);
		}

		//发送目标控制码
		Ioret = DeviceIoControl(hDevice, IOCODE, &IoCodeBuff, 0x4, NULL, NULL, &retLen, 0);
		if (!Ioret)
		{
			printf("Send Io error\n");
			return -1;
		}
		else
		{
			printf("ioCode:%x\n", ioCode);
		}
	}
	else if (j == 4)
	{
		//发送IRP处理函数rva
		Ioret = DeviceIoControl(hDevice, IOCODE2, &IrpFunRvaBuff, 0x4, NULL, NULL, &retLen, 0);
		if (!Ioret)
		{
			printf("Send Io error\n");
			return -1;
		}
		else
		{
			printf("IrpFunRva:%x\n", rva);
		}
	}
	else if (j == 5)
	{
		//发送目标模块名
		Ioret = DeviceIoControl(hDevice, IOCODE1, cBugSysName, inputlen, NULL, NULL, &retLen, 0);
		if (!Ioret)
		{
			printf("Send Io error\n");
			return -1;
		}
		else
		{
			printf("cBugSysName:%s inputlen:%d\n", cBugSysName, inputlen);
		}

		//发送IRP处理函数rva
		Ioret = DeviceIoControl(hDevice, IOCODE2, &IrpFunRvaBuff, 0x4, NULL, NULL, &retLen, 0);
		if (!Ioret)
		{
			printf("Send Io error\n");
			return -1;
		}
		else
		{
			printf("IrpFunRva:%x\n", rva);
		}
	}
	system("pause");
	return 0;
}