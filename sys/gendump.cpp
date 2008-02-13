//
// gr8 live kernel debugging driver (gr8lkdd)
//
// [C] Great, 2007. http://hellknights.void.ru/
//
// Посвящается ProTeuS'у в честь его дня рождения
//
// Dump controlling functions
//
/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ntifs.h"
#include "dumptypes.h"

#undef ExAllocatePool
#define ExAllocatePool(p,n) ExAllocatePoolWithTag( p, n, 'pmDG' )

#define MIN(a,b) ( (a > b) ? b : a )

NTSTATUS
WriteHeaderPage(
	IN PVOID Buffer,
	IN LARGE_INTEGER Offset,
	IN ULONG BufferSize,
	OUT PULONG Written
	);

NTSTATUS
WriteDumpPages(
	IN PVOID Buffer,
	IN LARGE_INTEGER Offset,
	IN ULONG BufferSize,
	OUT PULONG Written
	);

extern "C"
VOID
CalculateDumpSize(
	OUT PLARGE_INTEGER DumpSize
	);

extern "C"
NTSTATUS
InitializeDump();

VOID
FreeDump();

//
// Define discardable functions
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, InitializeDump)
#pragma alloc_text(INIT, CalculateDumpSize)
#endif

//
// Globals
//

struct DUMP_IN_MEMORY {
	BOOLEAN bInitialized;
	PDUMP_HEADER Header;
	PKD_DEBUGGER_DATA_BLOCK KdDebuggerDataBlock;
	CONTEXT      Context;
	EXCEPTION_RECORD Exception;
	PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
	LARGE_INTEGER SizeRequired;
};

static DUMP_IN_MEMORY Dump;

NTSTATUS
GetCurrentContext(
	PCONTEXT pCtx
	)
{
	CONTEXT ctx = {0};

	// Get context
	__asm
	{
		// Common registers
        mov [ctx.Eax], eax
		mov [ctx.Ebx], ebx
		mov [ctx.Ecx], ecx
		mov [ctx.Edx], edx
		mov [ctx.Esi], esi
		mov [ctx.Edi], edi

		// Control registers
		mov [ctx.Esp], esp
		mov [ctx.Ebp], ebp

		call _1
		// This address will appear in kd as crash address:
_1:		pop eax
		mov [ctx.Eip], eax

		pushfd
		pop eax
		mov [ctx.EFlags], eax

		// Debug registers
		__emit 0x0F
		__emit 0x21
		__emit 0xC0 ; mov eax, dr0
		mov [ctx.Dr0], eax
		__emit 0x0F
		__emit 0x21
		__emit 0xC8 ; mov eax, dr1
		mov [ctx.Dr1], eax
		__emit 0x0F
		__emit 0x21
		__emit 0xD0 ; mov eax, dr2
		mov [ctx.Dr2], eax
		__emit 0x0F
		__emit 0x21
		__emit 0xD8 ; mov eax, dr3
		mov [ctx.Dr3], eax
		__emit 0x0F
		__emit 0x21
		__emit 0xF0 ; mov eax, dr6
		mov [ctx.Dr6], eax
		__emit 0x0F
		__emit 0x21
		__emit 0xF8 ; mov eax, dr7
		mov [ctx.Dr7], eax

		// Segment registers
		push cs
		pop eax
        mov [ctx.SegCs], eax
		xor eax,eax
		mov ax, ss
		mov [ctx.SegSs], eax
		mov ax, ds
		mov [ctx.SegDs], eax
		mov ax, es
		mov [ctx.SegEs], eax
		mov ax, fs
		mov [ctx.SegFs], eax
		mov ax, gs
		mov [ctx.SegGs], eax
	}

	__try
	{
		*pCtx = ctx;
	}
	__except( EXCEPTION_EXECUTE_HANDLER ) 
	{
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}

//
// Determine if it's a free build of kernel
//
//   = 0xF  - free build
//   = 0xC  - checked build
//   = 0    - on error
//

ULONG
CheckedOrFree(
	)
{
	NTSTATUS Status;
    HANDLE hKey;
	UNICODE_STRING KeyName, ValueName;
	OBJECT_ATTRIBUTES oa;
	ULONG ReturnValue = 0;

	RtlInitUnicodeString( &KeyName, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" );
	InitializeObjectAttributes( &oa, &KeyName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, 0 );

    Status = ZwOpenKey (
		&hKey,
		KEY_QUERY_VALUE,
		&oa );

	if( !NT_SUCCESS(Status) )
		goto _exit;

	ULONG ResultLength = 0;
    BYTE* Buffer = (BYTE*) ExAllocatePool( PagedPool, 0x100 );
	if( Buffer == NULL )
	{
		ZwClose( hKey );
		goto _exit;
	}

	RtlInitUnicodeString( &ValueName, L"CurrentType" );

	Status = ZwQueryValueKey (
		hKey,
		&ValueName,
		KeyValueFullInformation,
		Buffer,
		0x100,
		&ResultLength );

    if( !NT_SUCCESS(Status) )
	{
		ExFreePool( Buffer );
		ZwClose( hKey );
		goto _exit;
	}

	__try
	{
		PKEY_VALUE_FULL_INFORMATION KeyFullInfo = (PKEY_VALUE_FULL_INFORMATION) Buffer;
		if( KeyFullInfo->Type == REG_SZ )
		{
			PWSTR Data = (PWSTR)( (ULONG)Buffer + KeyFullInfo->DataOffset );

			if( wcsstr( Data, L"Checked" ) != NULL )
				ReturnValue = 0xC;

			if( wcsstr( Data, L"Free" ) != NULL )
				ReturnValue = 0xF;
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
	}

	ExFreePool( Buffer );
    ZwClose( hKey );

_exit:
	return ReturnValue;
}

NTSTATUS
InitializeDump(
	)
{
	PVOID KeCapturePersistentThreadState;
	UNICODE_STRING uKeCapturePersistentThreadState;
	PDUMP_HEADER hdr;
	UNICODE_STRING uKeNumberProcessors;
	PUSHORT KeNumberProcessors;
	PEXCEPTION_POINTERS pei;
	PULONG blocks;

	if( Dump.bInitialized )
		return STATUS_SUCCESS;

	// Check build number
    if( *NtBuildNumber != 2600 )
	{
		KdPrint(("This driver works only with Windows XP SP2 Build 2600, your build number: %d\n", *NtBuildNumber));
		return STATUS_NOT_IMPLEMENTED;
	}

	//
	// Get KeNumberProcessors
	//

	RtlInitUnicodeString( &uKeNumberProcessors, L"KeNumberProcessors" );
    KeNumberProcessors = (PUSHORT) MmGetSystemRoutineAddress( &uKeNumberProcessors );

	if( KeNumberProcessors == NULL )
	{
		KdPrint(("Assertion failed for (KeNumberProcessors != NULL)\n"));
		return STATUS_INVALID_PARAMETER;
	}

	//
	// Get KeCapturePersistentThreadState address
	//

	RtlInitUnicodeString( &uKeCapturePersistentThreadState, L"KeCapturePersistentThreadState" );
	KeCapturePersistentThreadState = MmGetSystemRoutineAddress( &uKeCapturePersistentThreadState );
	if( KeCapturePersistentThreadState == NULL )
	{
		KdPrint(("Assetion failed for (KeCapturePersistentThreadState != NULL)\n"));
		return STATUS_INVALID_PARAMETER;
	}

	//
	// Allocate header page
	//

    hdr = Dump.Header = (PDUMP_HEADER) ExAllocatePool( NonPagedPool, PAGE_SIZE );
	if( Dump.Header == NULL )
	{
		KdPrint(("No resources available to allocate header page\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlFillMemoryUlong( hdr, PAGE_SIZE, 'EGAP' );

	//
	// Get debugger data block
	//

	__try {
		hdr->KdDebuggerDataBlock = *(PVOID*)((ULONG)KeCapturePersistentThreadState + *(ULONG*)((ULONG)KeCapturePersistentThreadState + 0xC )+ 0x11);

	} __except( (pei=GetExceptionInformation()) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_EXECUTE_HANDLER ) {
		ULONG i;

		KdPrint(("An exception occurred while trying to get KdDebuggerDataBlock address:\n"));
		KdPrint(("Exception code: 0x%08x\n", pei->ExceptionRecord->ExceptionCode));
		KdPrint(("Number of arguments: 0x%08x\n", pei->ExceptionRecord->NumberParameters));

		for( i = 0; i < pei->ExceptionRecord->NumberParameters; i++ ) {
			KdPrint(("Argument[%d]: 0x%08x\n", i, pei->ExceptionRecord->ExceptionInformation[i]));
		}

		ExFreePool( Dump.Header );

		return GetExceptionCode();
	}
	Dump.KdDebuggerDataBlock = (PKD_DEBUGGER_DATA_BLOCK) hdr->KdDebuggerDataBlock;

	// Check KdDebuggerDataBlock
	if( Dump.KdDebuggerDataBlock->ValidBlock != 'GBDK' || Dump.KdDebuggerDataBlock->Size != sizeof(*Dump.KdDebuggerDataBlock) )
	{
		// Invalid debugger data block
		KdPrint((	"KdDebuggerDataBlock is not valid.\nSignature = 0x%08x (should be 0x%08x)\nSize = 0x%08x (should be 0x%08x)\n",
					Dump.KdDebuggerDataBlock->ValidBlock, 'GBDK',
					Dump.KdDebuggerDataBlock->Size, sizeof(*Dump.KdDebuggerDataBlock) ));

		ExFreePool( Dump.Header );
		return STATUS_INVALID_PARAMETER;
	}

	// Get context
	GetCurrentContext( &Dump.Context );

	//
	// Fill header
	//

	hdr->ValidDump = 'PMUD';
	hdr->MinorVersion = (USHORT) *NtBuildNumber;
	hdr->MajorVersion = (USHORT) ( CheckedOrFree() == DUMP_MAJOR_CHECKED ? DUMP_MAJOR_CHECKED : DUMP_MAJOR_FREE );
	hdr->DirectoryTableBase = CR3();

	hdr->MachineImageType   = 0x14c;
	hdr->NumberProcessors   = *KeNumberProcessors;
	hdr->BugCheckCode       = KMODE_EXCEPTION_NOT_HANDLED;
	hdr->BugCheckParameter1 = STATUS_SINGLE_STEP;
	hdr->BugCheckParameter2 = Dump.Context.Eip;
	hdr->BugCheckParameter3 = 0;
	hdr->BugCheckParameter4 = 0;
	hdr->VersionUser[0] = '\0';
	hdr->PaeEnabled = (CR4() & PAE_ENABLED) ? TRUE : FALSE;

	hdr->PfnDataBase = (PULONG) Dump.KdDebuggerDataBlock->MmPfnDatabase.VirtualAddress;
	hdr->PsLoadedModuleList = (PLIST_ENTRY) Dump.KdDebuggerDataBlock->PsLoadedModuleList.VirtualAddress;
	hdr->PsActiveProcessHead = (PLIST_ENTRY) Dump.KdDebuggerDataBlock->PsActiveProcessHead.VirtualAddress;

	blocks = (ULONG*)(ULONG_PTR)Dump.Header;

	//
	// Get physical memory descriptor
	//

	Dump.MmPhysicalMemoryBlock = *(Dump.KdDebuggerDataBlock->MmPhysicalMemoryBlock.VirtualAddress);    

	if( Dump.MmPhysicalMemoryBlock->NumberOfRuns == 'EGAP' ) {
		RtlCopyMemory(	&blocks[ DH_PHYSICAL_MEMORY_BLOCK ],
						Dump.MmPhysicalMemoryBlock, 
						sizeof(PHYSICAL_MEMORY_DESCRIPTOR)
						);
	} else {
		RtlCopyMemory(	&blocks[ DH_PHYSICAL_MEMORY_BLOCK ],
						Dump.MmPhysicalMemoryBlock, 
						sizeof(PHYSICAL_MEMORY_DESCRIPTOR) - sizeof(PHYSICAL_MEMORY_RUN) + 
						sizeof(PHYSICAL_MEMORY_RUN)*Dump.MmPhysicalMemoryBlock->NumberOfRuns
						);
	}

	//
	// Save context record
	//

	Dump.Context.ContextFlags = CONTEXT_FULL;

	RtlCopyMemory(	&blocks[ DH_CONTEXT_RECORD ],
					&Dump.Context,
					sizeof(CONTEXT)
					);

	//
	// Create & store exception record
	//

	Dump.Exception.ExceptionCode = hdr->BugCheckParameter1;
	Dump.Exception.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	Dump.Exception.ExceptionRecord = NULL;
	Dump.Exception.ExceptionAddress = (PVOID) Dump.Context.Eip;
	Dump.Exception.NumberParameters = 0;

	RtlCopyMemory(	&blocks[ DH_EXCEPTION_RECORD ],
					&Dump.Exception,
					sizeof(EXCEPTION_RECORD)
					);

	//
	// Initialize dump type & size
	//

	blocks[ DH_DUMP_TYPE ] = DUMP_TYPE_COMPLETE;

	blocks[ DH_PRODUCT_TYPE ] = *(ULONG*)0xFFDF0264; // KUSER_SHARED_DATA->NtProductType
	blocks[ DH_SUITE_MASK ] = *(ULONG*)0xFFDF02D0; // KUSER_SHARED_DATA->SuiteMask
	*((LARGE_INTEGER*)&blocks[ DH_INTERRUPT_TIME ]) = *(LARGE_INTEGER*)0xFFDF0008; // KUSER_SHARED_DATA->InterruptTime
	*((LARGE_INTEGER*)&blocks[ DH_SYSTEM_TIME ]) = *(LARGE_INTEGER*)0xFFDF0014; // KUSER_SHARED_DATA->SystemTime

	blocks[ DH_CALLBACKS_STATUS ] = STATUS_SUCCESS;

	Dump.SizeRequired.QuadPart = ( Dump.MmPhysicalMemoryBlock->NumberOfPages << 12 ) + 0x1000;
    *((LARGE_INTEGER*)&blocks[DH_REQUIRED_DUMP_SPACE]) = Dump.SizeRequired;

	Dump.bInitialized = TRUE;

	return STATUS_SUCCESS;
}


VOID
FreeDump(
	)
{
	if( !Dump.bInitialized )
		return;

    ExFreePool( Dump.Header );
}

extern "C"
VOID
CalculateDumpSize(
	OUT PLARGE_INTEGER DumpSize
	)
{
	__try
	{
		*DumpSize = Dump.SizeRequired;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
	}
}

NTSTATUS
WriteHeaderPage(
	IN PVOID Buffer,
	IN LARGE_INTEGER Offset,
	IN ULONG BufferSize,
	OUT PULONG Written
	)
{
    __try
	{
		ULONG BytesToCopy = MIN( PAGE_SIZE-Offset.LowPart, BufferSize );

		memcpy( Buffer, (BYTE*)Dump.Header + Offset.LowPart, MIN( PAGE_SIZE, BufferSize ) );

		*Written = BytesToCopy;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
	return STATUS_SUCCESS;
}

//
// Map physical address to system space
//

PVOID
MmMapPageToSystemSpace(
	PFN_NUMBER PhysicalPFN
	)
{
	PHYSICAL_ADDRESS Pa;

	Pa.QuadPart = PhysicalPFN * PAGE_SIZE;

    return MmMapIoSpace( Pa, PAGE_SIZE, MmNonCached );
}

//
// Get physical PageFrameNumber for dump page
//

PFN_NUMBER GetPhysicalPFN( PFN_NUMBER DumpPFN )
{
	PFN_NUMBER iDumpPage, iPage = iDumpPage = DumpPFN;

	if( iDumpPage >= Dump.MmPhysicalMemoryBlock->NumberOfPages )
		return -1;

	ULONG NumberOfRunsRequired = 0;
	PFN_NUMBER TotalPageCount = 0;

	for( ; NumberOfRunsRequired<Dump.MmPhysicalMemoryBlock->NumberOfRuns; NumberOfRunsRequired++ )
	{
		PPHYSICAL_MEMORY_RUN Runs = Dump.MmPhysicalMemoryBlock->Run;

		if( iDumpPage >= TotalPageCount &&
			iDumpPage < TotalPageCount + Runs[NumberOfRunsRequired].PageCount )
			break;

		TotalPageCount += (Runs[NumberOfRunsRequired].PageCount);
	}

	PFN_NUMBER PreviousEnd = 0;
	NumberOfRunsRequired ++;

	for( ULONG i=0; i<NumberOfRunsRequired; i++ )
	{
		PPHYSICAL_MEMORY_RUN Runs = Dump.MmPhysicalMemoryBlock->Run;

		iPage += (Runs[i].BasePage - PreviousEnd);
		PreviousEnd = Runs[i].BasePage + Runs[i].PageCount;
	}

	return iPage - 1;
}

NTSTATUS
WriteDumpPages(
	IN PVOID Buffer,
	IN LARGE_INTEGER Offset,
	IN ULONG BufferSize,
	OUT PULONG Written
	)
{
	NTSTATUS Status = STATUS_SUCCESS;

    __try
	{
		if( Offset.QuadPart + BufferSize > Dump.SizeRequired.QuadPart )
		{
			return STATUS_END_OF_FILE;
		}

		// Number of page in dump
		PFN_NUMBER iPage, iBuffPage = (PFN_NUMBER) (Offset.QuadPart >> 12);
		PFN_NUMBER nPages = BufferSize >> 12;

		BOOLEAN LastPageIsNotFull = FALSE, FirstPageIsNotFull = FALSE;

		if( BufferSize & 0xFFF ) {
			nPages++;
			LastPageIsNotFull = TRUE;
		}

		if( Offset.LowPart & 0xFFF ) {
			FirstPageIsNotFull = TRUE;
		}
		
		iPage = GetPhysicalPFN( iBuffPage );

		if( iPage == -1 )
			return STATUS_INVALID_PARAMETER;

		BOOLEAN WritingIncrementedPage = FALSE;
		ULONG IncrementedPageSize = 0;

		// Start writing pages
		for(	PFN_NUMBER MemoryPosition=iPage, BufferPosition=iBuffPage;
				BufferPosition < iBuffPage + nPages;
				BufferPosition++ )
		{
			PVOID CurrentPage = MmMapPageToSystemSpace( MemoryPosition );

			ULONG PageOffset = 0;
			ULONG nBytesToCopy = PAGE_SIZE;

			if( LastPageIsNotFull && BufferPosition == (iBuffPage + nPages - 1) ) {
				
				//
				// Last page is not full
				//

				nBytesToCopy = BufferSize & 0xFFF;

				if( WritingIncrementedPage )
				{
					nBytesToCopy = IncrementedPageSize;
				}
				else if( FirstPageIsNotFull ) {

					IncrementedPageSize = (BufferSize & 0xFFF) - (PAGE_SIZE - Offset.LowPart & 0xFFF);

					if( ((LONG)IncrementedPageSize) > 0 ) {
						nBytesToCopy = PAGE_SIZE;

						nPages ++;
						WritingIncrementedPage = TRUE;
						
					}
					else // < 0
					{
						nBytesToCopy +=  (Offset.LowPart & 0xFFF);
					}
				}
			}

			if( FirstPageIsNotFull && BufferPosition == iBuffPage ) {
				
				//
				// First page should be copied not from the beginning
				//

				PageOffset = Offset.LowPart & 0xFFF;
				nBytesToCopy = PAGE_SIZE - PageOffset;
				
				if( CurrentPage )
				{
					memcpy( Buffer, (PVOID)( (ULONG)CurrentPage + PageOffset ), nBytesToCopy );
					MmUnmapIoSpace( CurrentPage, PAGE_SIZE );
				}
				else {
					memset( Buffer, 0, nBytesToCopy );
				}

				KdPrint(("First short page written, iBuffPage=%x, iPage=%x, Size=%x\n", BufferPosition, MemoryPosition, nBytesToCopy));

				*(ULONG*)&Buffer &= 0xFFFFF000;
			}
			else
			{
				if( CurrentPage )
				{
					memcpy( (PVOID)( (ULONG)Buffer + ((BufferPosition-iBuffPage) << 12) ), CurrentPage, nBytesToCopy );
					MmUnmapIoSpace( CurrentPage, PAGE_SIZE );
				}
				else {
					// Mapping failed, write zero page
					memset( (PVOID)( (ULONG)Buffer + ((BufferPosition-iBuffPage) << 12) ), 0, nBytesToCopy );
				}

				KdPrint(("Page written, iBuffPage=%x, iPage=%x, Size=%x\n", BufferPosition, MemoryPosition, nBytesToCopy));
			}

			*Written += nBytesToCopy;

			MemoryPosition ++;

			// Check if MemoryPosition is on physical memory run boundary
			for( ULONG i=0; i<Dump.MmPhysicalMemoryBlock->NumberOfRuns; i++ )
			{
				PPHYSICAL_MEMORY_RUN Runs = Dump.MmPhysicalMemoryBlock->Run;

				if( MemoryPosition == Runs[i].BasePage + Runs[i].PageCount )
				{
					// On boundary, go to next memory run if possible

					if( i == Dump.MmPhysicalMemoryBlock->NumberOfRuns - 1 ) {
						// End of physical memory
						goto __end_writing;
					}

					// Go to next memory run
					MemoryPosition += Runs[i+1].BasePage - (Runs[i].BasePage + Runs[i].PageCount);

					break;
				}
			}
		}

__end_writing:

		NOTHING;
	
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	return Status;
}

















