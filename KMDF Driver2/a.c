#pragma warning(disable:4100)
#pragma warning(disable:4996)

#include <ntifs.h>
#include <intrin.h>
#include "infinityhook.h"

#pragma comment(lib, "libinfinityhook.lib")

typedef NTSTATUS(*NtCreateFile_t)(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
	);
typedef NTSTATUS(*NtWriteFile_t)(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
	);

NtCreateFile_t TrueNtCreateFile;
NtWriteFile_t TrueNtWriteFile;
int installMode = TRUE;

struct _LBconfig
{
	PWCH source;
	PWCH dest;
	ULONG32 sourceLen; //单位: sizeof(WCHAR),不包含\0.
	ULONG32 destLen;
} * LBconfig;
ULONG LBconfigLen;


#pragma code_seg("PAGE")
VOID Unload(_In_ PDRIVER_OBJECT DriverObject)
{
	IfhRelease();

	ExFreePool(LBconfig[0].source);
	ExFreePool(LBconfig);
	return;
}


/*
ObjectName：要替换成的路径 \??\开头
pObjectNameMDL：赋值NULL
originalName：替换下来的内存，返回的时候要换回去
*/
NTSTATUS ChangeCreateFileBuffer(PWCHAR* ObjectName, ULONG32 ObjectNameLen, PMDL* pObjectNameMDL, POBJECT_ATTRIBUTES ObjectAttributes, PUNICODE_STRING originalName)
{
	PWCHAR r3ObjectName = NULL;
	//潜在的内存溢出错误（size_t -> ULONG)
	*pObjectNameMDL = IoAllocateMdl(*ObjectName, (ULONG)(wcslen(*ObjectName) * sizeof(wchar_t) + sizeof(wchar_t)), FALSE, FALSE, NULL);
	if (*pObjectNameMDL == NULL)
	{
		DbgPrint("[-] infinityhook: IoAllocateMdl error\n");
		return STATUS_UNSUCCESSFUL;
	}
	MmBuildMdlForNonPagedPool(*pObjectNameMDL);
	__try
	{
		r3ObjectName = (PWCHAR)MmMapLockedPagesSpecifyCache(*pObjectNameMDL, UserMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[-] infinityhook: MmMapLockedPagesSpecifyCache error %lu\n", GetExceptionCode());
		return STATUS_UNSUCCESSFUL;
	}
	if (r3ObjectName == NULL) {
		DbgPrint("[-] infinityhook: MmMapLockedPagesSpecifyCache error NULL\n");
		return STATUS_UNSUCCESSFUL;
	}
	originalName->Buffer = ObjectAttributes->ObjectName->Buffer;
	originalName->Length = ObjectAttributes->ObjectName->Length;
	originalName->MaximumLength = ObjectAttributes->ObjectName->MaximumLength;

	ObjectAttributes->ObjectName->Buffer = r3ObjectName;
	ObjectAttributes->ObjectName->Length = (USHORT)(ObjectNameLen * sizeof(wchar_t));
	ObjectAttributes->ObjectName->MaximumLength = (USHORT)(ObjectNameLen * sizeof(wchar_t) + sizeof(wchar_t));

	return STATUS_SUCCESS;
}

NTSTATUS MyCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{
	NTSTATUS s;
	UNICODE_STRING originalName = { 0 };
	int isChangeBuffer = 0;
	PWCHAR ObjectName = NULL;
	PMDL pObjectNameMDL = NULL;
	
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		ObjectName = (PWCHAR)ExAllocatePool(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			//安装模式：CreateFile C:\lb2ih-install\ 。
			if (installMode == TRUE && wcsstr(ObjectName, L"C:\\lb2ih-install\\") != NULL /* && wcslen(ObjectName) > 23*/)
			{
				//给句柄赋个特殊值，直接返回。
				//开始hook writefile，比对handle，截取写入内容，追加存储到pLBconfigFile，分析内容，转储到LBconfig。

#define installing 2
				_mm_mfence();
				installMode = installing;
				*FileHandle = (HANDLE)'LBIH';
				//__debugbreak();
				IoStatusBlock->Status = STATUS_SUCCESS;
				ExFreePool(ObjectName);
				return STATUS_SUCCESS;
			}
			//if (installMode)
			//{
			//	ExFreePool(ObjectName);
			//	goto end;
			//}

			//
			// L"\\Device\\HarddiskVolume1\\Users\\Default.DESKTOP-T6R0PTA\\Desktop\\1\\2.txt"
			//real：\??\C:\Users\Default.DESKTOP-T6R0PTA\Desktop\1\1.txt
			//PWCH p = wcsstr(ObjectName, L"\\Users\\Default.DESKTOP-T6R0PTA\\Desktop\\1\\1.txt");
			if (installMode == FALSE)
			{
				for (size_t i = 0; i < LBconfigLen; i++)
				{
					if (wcsstr(ObjectName, LBconfig[i].source))
					{
						__debugbreak();

						DbgPrint("[+] infinityhook:  %wZ.\n", ObjectAttributes->ObjectName);

						if ((s = ChangeCreateFileBuffer(&(LBconfig[i].dest), LBconfig[i].destLen, &pObjectNameMDL, ObjectAttributes, &originalName)) != STATUS_SUCCESS)
						{
							return STATUS_UNSUCCESSFUL;
						}
						isChangeBuffer = 1;
						DbgPrint("[-] infinityhook:  %wZ.\n", ObjectAttributes->ObjectName);

						goto end;
					}
				}
			}
			
			
			ExFreePool(ObjectName);
		}
	}

	end:
	s = TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (isChangeBuffer)
	{
		ObjectAttributes->ObjectName->Buffer = originalName.Buffer;
		ObjectAttributes->ObjectName->Length = originalName.Length;
		ObjectAttributes->ObjectName->MaximumLength = originalName.MaximumLength;
		IoFreeMdl(pObjectNameMDL);
		ExFreePool(ObjectName);
		//__debugbreak();
	}
	

	return s;
}

NTSTATUS MyWriteFile(
	_In_ HANDLE FileHandle,
	_In_opt_ HANDLE Event,
	_In_opt_ PIO_APC_ROUTINE ApcRoutine,
	_In_opt_ PVOID ApcContext,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_reads_bytes_(Length) PVOID Buffer,
	_In_ ULONG Length,
	_In_opt_ PLARGE_INTEGER ByteOffset,
	_In_opt_ PULONG Key
)
{
	if (installMode == installing && FileHandle == (HANDLE)'LBIH')
	{
		PWCHAR pLBconfigFile = (PWCHAR)ExAllocatePool(NonPagedPool, Length);
		if (pLBconfigFile == NULL)
		{
			DbgPrint("LB2IH!pLBconfigFile ExAllocatePool NULL\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		memcpy(pLBconfigFile, Buffer, Length);
		PWCHAR pLBconfigFileTmp = pLBconfigFile;
		//每组路径由\r\n分割，全替换成\0，一组中的两个路径由>分割，也替换成\0。
			//先遍历换行，赋值到source，再遍历问号，分割出dest。
		do
		{
			LBconfigLen++;

			pLBconfigFileTmp = wcsstr(pLBconfigFileTmp, L"\r\n");
			if (pLBconfigFileTmp == NULL)
			{
				break;
			}
			pLBconfigFileTmp += 2;
		} while (TRUE);
		//__debugbreak();
		LBconfig = ExAllocatePool(NonPagedPool, LBconfigLen * sizeof(struct _LBconfig));
		if (LBconfig == NULL)
		{
			DbgPrint("LB2IH!LBconfig ExAllocatePool NULL\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		pLBconfigFileTmp = pLBconfigFile;
		PWCHAR destTmp = NULL;
		for (ULONG i = 0; i < LBconfigLen; i++)
		{
			LBconfig[i].source = pLBconfigFileTmp;
			destTmp = wcsstr(pLBconfigFileTmp, L">");
			if (destTmp == NULL)
			{
				DbgPrint("LB2IH!input format error!");
				return STATUS_UNSUCCESSFUL;
			}
			destTmp[0] = L'\0';
			destTmp += 1;
			LBconfig[i].dest = destTmp;

			pLBconfigFileTmp = wcsstr(destTmp, L"\r\n");
			if (pLBconfigFileTmp == NULL)
			{
				LBconfig[i].sourceLen = (ULONG32)wcslen(LBconfig[i].source);
				LBconfig[i].destLen = (ULONG32)wcslen(LBconfig[i].dest);
				break;
			}
			pLBconfigFileTmp[0] = L'\0';
			pLBconfigFileTmp[1] = L'\0';
			pLBconfigFileTmp += 2;

			LBconfig[i].sourceLen = (ULONG32)wcslen(LBconfig[i].source);
			LBconfig[i].destLen = (ULONG32)wcslen(LBconfig[i].dest);
		}
		//__debugbreak();

		_mm_mfence();
		installMode = FALSE;

		IoStatusBlock->Status = STATUS_SUCCESS;
		return STATUS_SUCCESS;
	}
	
	return TrueNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

void IHCallback(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	if (*SystemCallFunction == TrueNtCreateFile)
	{
		*SystemCallFunction = (void*)MyCreateFile;
	}
	if (installMode == installing)
	{
		if (*SystemCallFunction == TrueNtWriteFile)
		{
			*SystemCallFunction = (void*)MyWriteFile;
		}
	}
	return;
}

#pragma code_seg("INIT")
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	DriverObject->DriverUnload = Unload;
	UNICODE_STRING NCF = RTL_CONSTANT_STRING(L"NtCreateFile");
	TrueNtCreateFile = (NtCreateFile_t)MmGetSystemRoutineAddress(&NCF);
	if (!TrueNtCreateFile)
	{
		DbgPrint("LB2IH!TrueNtCreateFile == NULL\n");
		return STATUS_UNSUCCESSFUL;
	}
	UNICODE_STRING NWF = RTL_CONSTANT_STRING(L"NtWriteFile");
	TrueNtWriteFile = (NtWriteFile_t)MmGetSystemRoutineAddress(&NWF);
	if (!TrueNtWriteFile)
	{
		DbgPrint("LB2IH!TrueNtWriteFile == NULL\n");
		return STATUS_UNSUCCESSFUL;
	}
	

	NTSTATUS s = IfhInitialize(IHCallback);
	if (!NT_SUCCESS(s))
	{
		DbgPrint("LB2IH!Failed to initialize infinityhook with status: 0x%lx.\n", s);
	}

	return s;

}