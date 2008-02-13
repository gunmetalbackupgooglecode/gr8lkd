//
// gr8 live kernel debugging driver (gr8lkdd)
//
// [C] Great, 2007. http://hellknights.void.ru/
//
// Посвящается ProTeuS'у в честь его дня рождения
//
// Main source file
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

#undef ExAllocatePool
#define ExAllocatePool(p,n) ExAllocatePoolWithTag( p, n, 'tFsF' )

typedef BOOLEAN BOOL;
typedef unsigned char BYTE, *PBYTE;

extern "C" 
{
	int __cdecl _snprintf( char*, int, char*, ... );

	NTSTATUS 
	NTAPI
    IoSetCompletionRoutineEx(
		IN PDEVICE_OBJECT  DeviceObject,
		IN PIRP  Irp,
		IN PIO_COMPLETION_ROUTINE  CompletionRoutine,
		IN PVOID  Context,
		IN BOOLEAN    InvokeOnSuccess,
		IN BOOLEAN  InvokeOnError,
		IN BOOLEAN  InvokeOnCancel
    );
}

// Up-Case latin char
#define UPCASE(c) (  ( c >= 'a' && c <= 'z' ) ? ( c + 'A' - 'a' ) : c )


LONG
CompareUnicodeString(
    IN PUNICODE_STRING String1,
    IN PUNICODE_STRING String2,
    IN BOOLEAN CaseInSensitive
    )

/*++

Routine Description:

  CompareUnicodeString() compares one unicode string with another

Arguments:

  String1
  String2
    Input unicode strings

  CaseInSensitive
    TRUE in case of case-insensitive comparsion

Return value:

    Signed value that gives the results of the comparison:

        Zero - String1 equals String2

        < Zero - String1 less than String2

        > Zero - String1 greater than String2

--*/

{

    PWCHAR s1, s2, Limit;
    LONG n1, n2;
    WCHAR c1, c2;

    s1 = String1->Buffer;
    s2 = String2->Buffer;
    n1 = String1->Length;
    n2 = String2->Length;

    ASSERT((n1 & 1) == 0);
    ASSERT((n2 & 1) == 0);
    ASSERT(!(((((ULONG_PTR)s1 & 1) != 0) || (((ULONG_PTR)s2 & 1) != 0)) && (n1 != 0) && (n2 != 0)));

    Limit = (PWCHAR)((PCHAR)s1 + (n1 <= n2 ? n1 : n2));
    
    while (s1 < Limit) {
        c1 = *s1++;
        c2 = *s2++;
        if (c1 != c2) {

			if (CaseInSensitive) {
				c1 = UPCASE(c1);
				c2 = UPCASE(c2);

				if (c1 != c2) {
					return (LONG)(c1) - (LONG)(c2);
				}
			}
			else return (LONG)(c1) - (LONG)(c2);
        }
    }

    return n1 - n2;
}

#define RtlCompareUnicodeString CompareUnicodeString

#define MIN(a,b) ( (a > b) ? b : a )

#if DBG

NTSTATUS
UnicodeToMultiByte(
	IN  PUNICODE_STRING String,
	OUT PCHAR Buffer,
	IN  OUT PULONG BufferLength
	)

/*++

Routine Description:

  UnicodeToMultiByte() converts unicode string to multi-byte zero-terminated ANSI string

Arguments:
  
  String
	Unicode string structure, representing input string

  Buffer
    Pointer to output buffer

  BufferLength
	Pointer to unsigned long, containing on input maximum length of output buffer
	and receiving on output number of actually written characters

Return value:

  NT Status code describing operation status

--*/

{
    ULONG CapturedMaximumLength;
	ULONG i,n;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ASSERT( ( String->Length & 1) == 0 );

	__try
	{
		CapturedMaximumLength = *BufferLength;

		n = MIN( CapturedMaximumLength-1, (ULONG) (String->Length / 2) );
		n >>= 1;
        
		for( i=0; i<n; i++ )
		{
			Buffer[ i ] = (CHAR) String->Buffer[ i ];
		}

        Buffer[ i ] = '\0';

        *BufferLength = ++i;

		Status = STATUS_SUCCESS;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		Status = GetExceptionCode();
		KdPrint(("UnicodeToMultiByte(): Exception %08x occurred\n", Status));
	}

    return Status;		
}

#endif

typedef struct _FILTER_DEVICE_EXTENSION
{
    PDEVICE_OBJECT            AttachedToDeviceObject;
}
FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

extern "C"
NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	);

NTSTATUS
CreateDumpFile(
	);

NTSTATUS
DeleteDumpFile(
	);

//
// Define discardable functions
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

#define DISCARDABLE_ROUTINE  extern "C"


//
// Globals
//

UNICODE_STRING                gusDeviceName = {0};
UNICODE_STRING                gusDosDeviceName = {0};

// CDO
PDEVICE_OBJECT                gpdControl = NULL;

// Filter device
PDEVICE_OBJECT                gpdFilterDeviceObject = NULL;

// Driver object
PDRIVER_OBJECT                gpDriverObject = NULL;

#if DBG
struct CONST_DESCRIPTION {
	ULONG	Value;
	LPSTR	Desc;
#define DEFINE_STRING(x) { x, #x }
#define TABLE_END { 0, 0 }
};

#define FILESYSAPI extern "C"

CONST_DESCRIPTION IrpTypes[] = {
	DEFINE_STRING( IRP_MJ_CREATE ),
	DEFINE_STRING( IRP_MJ_CREATE_NAMED_PIPE ),
	DEFINE_STRING( IRP_MJ_CLOSE ),
	DEFINE_STRING( IRP_MJ_READ ),
	DEFINE_STRING( IRP_MJ_WRITE ),
	DEFINE_STRING( IRP_MJ_QUERY_INFORMATION ),
	DEFINE_STRING( IRP_MJ_SET_INFORMATION ),
	DEFINE_STRING( IRP_MJ_QUERY_EA ),
	DEFINE_STRING( IRP_MJ_SET_EA ),
	DEFINE_STRING( IRP_MJ_FLUSH_BUFFERS ),
	DEFINE_STRING( IRP_MJ_QUERY_VOLUME_INFORMATION ),
	DEFINE_STRING( IRP_MJ_SET_VOLUME_INFORMATION ),
	DEFINE_STRING( IRP_MJ_DIRECTORY_CONTROL ),
	DEFINE_STRING( IRP_MJ_FILE_SYSTEM_CONTROL ),
	DEFINE_STRING( IRP_MJ_DEVICE_CONTROL ),
	DEFINE_STRING( IRP_MJ_INTERNAL_DEVICE_CONTROL ),
	DEFINE_STRING( IRP_MJ_SHUTDOWN ),
	DEFINE_STRING( IRP_MJ_LOCK_CONTROL ),
	DEFINE_STRING( IRP_MJ_CLEANUP ),
	DEFINE_STRING( IRP_MJ_CREATE_MAILSLOT ),
	DEFINE_STRING( IRP_MJ_QUERY_SECURITY ),
	DEFINE_STRING( IRP_MJ_SET_SECURITY ),
	DEFINE_STRING( IRP_MJ_POWER ),
	DEFINE_STRING( IRP_MJ_SYSTEM_CONTROL ),
	DEFINE_STRING( IRP_MJ_DEVICE_CHANGE ),
	DEFINE_STRING( IRP_MJ_QUERY_QUOTA ),
	DEFINE_STRING( IRP_MJ_SET_QUOTA ),
	DEFINE_STRING( IRP_MJ_PNP ),
	TABLE_END
};

CONST_DESCRIPTION FileFsInformationClass[] = {
	DEFINE_STRING( FileFsAttributeInformation ),
	DEFINE_STRING( FileFsControlInformation ),
	DEFINE_STRING( FileFsDeviceInformation ),
	DEFINE_STRING( FileFsFullSizeInformation ),
	DEFINE_STRING( FileFsObjectIdInformation ),
	DEFINE_STRING( FileFsSizeInformation ),
	DEFINE_STRING( FileFsVolumeInformation ),
	TABLE_END
};

CONST_DESCRIPTION FileInformationClass[] = {
    DEFINE_STRING( FileDirectoryInformation ),       // 1
    DEFINE_STRING( FileFullDirectoryInformation ),   // 2
    DEFINE_STRING( FileBothDirectoryInformation ),   // 3
    DEFINE_STRING( FileBasicInformation ),           // 4 wdm
    DEFINE_STRING( FileStandardInformation ),        // 5 wdm
    DEFINE_STRING( FileInternalInformation ),        // 6
    DEFINE_STRING( FileEaInformation ),              // 7
    DEFINE_STRING( FileAccessInformation ),          // 8
    DEFINE_STRING( FileNameInformation ),            // 9
    DEFINE_STRING( FileRenameInformation ),          // 10
    DEFINE_STRING( FileLinkInformation ),            // 11
    DEFINE_STRING( FileNamesInformation ),           // 12
    DEFINE_STRING( FileDispositionInformation ),     // 13
    DEFINE_STRING( FilePositionInformation ),        // 14 wdm
    DEFINE_STRING( FileFullEaInformation ),          // 15
    DEFINE_STRING( FileModeInformation ),            // 16
    DEFINE_STRING( FileAlignmentInformation ),       // 17
    DEFINE_STRING( FileAllInformation ),             // 18
    DEFINE_STRING( FileAllocationInformation ),      // 19
    DEFINE_STRING( FileEndOfFileInformation ),       // 20 wdm
    DEFINE_STRING( FileAlternateNameInformation ),   // 21
    DEFINE_STRING( FileStreamInformation ),          // 22
    DEFINE_STRING( FilePipeInformation ),            // 23
    DEFINE_STRING( FilePipeLocalInformation ),       // 24
    DEFINE_STRING( FilePipeRemoteInformation ),      // 25
    DEFINE_STRING( FileMailslotQueryInformation ),   // 26
    DEFINE_STRING( FileMailslotSetInformation ),     // 27
    DEFINE_STRING( FileCompressionInformation ),     // 28
    DEFINE_STRING( FileObjectIdInformation ),        // 29
    DEFINE_STRING( FileCompletionInformation ),      // 30
    DEFINE_STRING( FileMoveClusterInformation ),     // 31
    DEFINE_STRING( FileQuotaInformation ),           // 32
    DEFINE_STRING( FileReparsePointInformation ),    // 33
    DEFINE_STRING( FileNetworkOpenInformation ),     // 34
    DEFINE_STRING( FileAttributeTagInformation ),    // 35
    DEFINE_STRING( FileTrackingInformation ),        // 36
    DEFINE_STRING( FileIdBothDirectoryInformation ), // 37
    DEFINE_STRING( FileIdFullDirectoryInformation ), // 38
	TABLE_END
};

//
// Debugging helper functions
//

FILESYSAPI
LPSTR
LookupConstDesc( CONST_DESCRIPTION* Table, ULONG Value )
{
	while( Table->Desc ) {
		if( Table->Value == Value ) {
			return Table->Desc;
		}
		Table ++;
	}
	return "(unknown)";
}
#endif

#define ALLOCATION_SIZE 0x00000800

struct
{
	PWSTR NameBuffer;
	PWSTR DirectoryNameBuffer;

	UNICODE_STRING Name;          //  \\filename.ext
	UNICODE_STRING RawName;       //  filename.ext
	UNICODE_STRING DirectoryName; //  \\ 
	UNICODE_STRING FullName;      //  \\DosDevices\\A:\\filename.ext

	LARGE_INTEGER Size;

} VirtualFile;

#define KeQuerySystemTime( x ) { (x)->QuadPart = 0; }

BOOLEAN EnableIrpFiltering = FALSE;

NTSTATUS FillBasicInfo( PFILE_BASIC_INFORMATION BasicInfo )
{
	RtlZeroMemory( BasicInfo, sizeof(*BasicInfo) );
	
	KeQuerySystemTime( &BasicInfo->LastWriteTime );
	KeQuerySystemTime( &BasicInfo->LastAccessTime );
	KeQuerySystemTime( &BasicInfo->CreationTime );

	BasicInfo->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;
	return STATUS_SUCCESS;
}

NTSTATUS FillStandardInfo( PFILE_STANDARD_INFORMATION StandardInfo )
{
	RtlZeroMemory( StandardInfo, sizeof(*StandardInfo) );

	StandardInfo->EndOfFile = VirtualFile.Size;
	StandardInfo->AllocationSize.LowPart = ALLOCATION_SIZE;
	StandardInfo->NumberOfLinks = 1;

	return STATUS_SUCCESS;
}

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


NTSTATUS Read( PFILE_OBJECT FileObject, PVOID Buffer, ULONG BufferSize, LARGE_INTEGER Offset, ULONG* Returned )
{
	NTSTATUS Status;

#if DBG
	__try {
		//__asm int 3;
	}
	__except( EXCEPTION_EXECUTE_HANDLER ) 
	{
	}
#endif

	*Returned = 0;

	__try
	{
		__try 
		{
			if( Offset.QuadPart + BufferSize >= VirtualFile.Size.QuadPart )
				return STATUS_END_OF_FILE;

			/*if( Offset.QuadPart % PAGE_SIZE )
				return STATUS_DATATYPE_MISALIGNMENT;*/

			/*if( BufferSize % PAGE_SIZE )
				return STATUS_DATATYPE_MISALIGNMENT;*/

			// No support for RAM > 4Gb
			if( Offset.HighPart )
				return STATUS_END_OF_FILE;

			if( Offset.LowPart < PAGE_SIZE )
			{
				ULONG Written = 0;

				Status = WriteHeaderPage( Buffer, Offset, BufferSize, &Written );
				*Returned = Written;

				if( BufferSize <= PAGE_SIZE || !NT_SUCCESS(Status) )
					return Status;

				Written = 0;

				Status = WriteDumpPages( (PVOID)( (ULONG)Buffer + PAGE_SIZE ), Offset, BufferSize - PAGE_SIZE, &Written );
				*Returned += Written;

				return Status;
			}

			return WriteDumpPages( Buffer, Offset, BufferSize, Returned );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			return GetExceptionCode();
		}
	}
	__finally
	{
		FileObject->CurrentByteOffset.QuadPart += *Returned;
	}
}

//
// IRP dispatchers
//

#include "irphandlers.h"

//
// Fast I/O dispatch handlers
//

#include "fastio.h"


NTSTATUS
CreateDumpFile(
	)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES oa;
	HANDLE hFile;
	IO_STATUS_BLOCK IoStatus;

	InitializeObjectAttributes( &oa, &VirtualFile.FullName, OBJ_KERNEL_HANDLE, 0, 0 );

	Status = ZwCreateFile(	&hFile,
							GENERIC_READ | GENERIC_WRITE,
							&oa,
							&IoStatus,
							NULL,
                            FILE_ATTRIBUTE_NORMAL,
							0,
							FILE_OVERWRITE_IF,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0 );

    if( NT_SUCCESS(Status) )
		ZwClose( hFile );
    
	return Status;
}

NTSTATUS
DeleteDumpFile(
	)
{
	OBJECT_ATTRIBUTES oa;

	InitializeObjectAttributes( &oa, &VirtualFile.FullName, OBJ_KERNEL_HANDLE, 0, 0 );

	return ZwDeleteFile( &oa );
}

#if DBG
// Unload routine
void DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    KdPrint (("[~] DriverUnload()\r\n"));

	// Detach & delete attaching device
	IoDetachDevice( ((PFILTER_DEVICE_EXTENSION) gpdFilterDeviceObject->DeviceExtension)->AttachedToDeviceObject );
	IoDeleteDevice( gpdFilterDeviceObject );

	FreeDump( );

	DeleteDumpFile( );

	ExFreePool( VirtualFile.FullName.Buffer );
   
	// Delete CDO
    IoDeleteSymbolicLink (&gusDosDeviceName);
    IoDeleteDevice (gpdControl);
}
#endif

NTSTATUS
OpenDriveByLetter (
    IN PWSTR     DriveName,
    OUT PDEVICE_OBJECT    *DeviceObject,
	OUT PFILE_OBJECT      *FileObject, // file object that should be dereferenced
	OUT PHANDLE           FileHandle  // file handle that should be closed
)
{
	OBJECT_ATTRIBUTES DeviceObjectAttributes;
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatus;
	UNICODE_STRING ObjectName;

	RtlInitUnicodeString( &ObjectName, DriveName );
	InitializeObjectAttributes( &DeviceObjectAttributes, &ObjectName, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, 0, 0 );

    Status = ZwCreateFile (
		FileHandle,
		FILE_READ_ATTRIBUTES,
		&DeviceObjectAttributes,
		&IoStatus,
		(PLARGE_INTEGER) NULL,
		0,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_DIRECTORY_FILE,
		0,
		0 );

	if( !NT_SUCCESS(Status) )
	{
		return Status;
	}

	Status = ObReferenceObjectByHandle (
		*FileHandle,
		FILE_READ_ATTRIBUTES,
		0,
		KernelMode,
		(PVOID*) FileObject,
		NULL );

	if( !NT_SUCCESS(Status) )
	{
		ZwClose( *FileHandle );
		return Status;
	}

	*DeviceObject = IoGetRelatedDeviceObject( *FileObject );

	if( *DeviceObject == NULL )
	{
		ObDereferenceObject( *FileObject );
		ZwClose( *FileHandle );
		return STATUS_UNSUCCESSFUL;
	}

	return Status;
}

// Driver entry point
DISCARDABLE_ROUTINE
NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
	)
{
    NTSTATUS status = STATUS_ACCESS_DENIED;
	PFAST_IO_DISPATCH fastIoDispatch;
	PWSTR AttachToName = L"\\DosDevices\\C:\\";

	KdPrint (("[~] DriverEntry()\r\n"));

	//
	// Initialize virtual file
	//

	VirtualFile.NameBuffer = L"\\gr8lkd.dmp";
	VirtualFile.DirectoryNameBuffer = L"\\";

	RtlInitUnicodeString( &VirtualFile.Name, VirtualFile.NameBuffer );
	RtlInitUnicodeString( &VirtualFile.DirectoryName, VirtualFile.DirectoryNameBuffer );
	RtlInitUnicodeString( &VirtualFile.RawName, VirtualFile.Name.Buffer + 1 );

	VirtualFile.FullName.Length = 0;
	VirtualFile.FullName.MaximumLength = 0x100;
	VirtualFile.FullName.Buffer = (PWSTR) ExAllocatePool( NonPagedPool, VirtualFile.FullName.MaximumLength );

	RtlAppendUnicodeToString( &VirtualFile.FullName, AttachToName );
	RtlAppendUnicodeStringToString( &VirtualFile.FullName, &VirtualFile.RawName );

	//
	// Initialize dump
	//

	status = InitializeDump( );
	
	if( !NT_SUCCESS(status) )
	{
		KdPrint(("Dump initialization failed with status %08x\n", status));
		return status;
	}

	CalculateDumpSize( &VirtualFile.Size );

    gpDriverObject = DriverObject;

	//
	// Create CDO
	//
    RtlInitUnicodeString (&gusDeviceName, L"\\FileSystem\\gr8lkdd_cdo");
    RtlInitUnicodeString (&gusDosDeviceName, L"\\??\\gr8lkdd_cdo");

    status = IoCreateDevice (
        DriverObject,
        0,
        &gusDeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &gpdControl);
    
    if (! NT_SUCCESS (status))
    {
        KdPrint (("IoCreateDevice() failed with status %08X\r\n", status));

        return STATUS_UNSUCCESSFUL;
    }

    status = IoCreateSymbolicLink (
        &gusDosDeviceName,
        &gusDeviceName);

    if (! NT_SUCCESS (status))
    {
        KdPrint (("IoCreateSymbolicLink() failed with status %08X\r\n", status));

        IoDeleteDevice (gpdControl);
        return STATUS_UNSUCCESSFUL;
    }

	//
	// Register dispatch routines
	//

	for( int i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++ )
		DriverObject -> MajorFunction[ i ] = FsftFsDispatch;

	//
	// Register unload routine only in the debug build
	//
	// WARNING: unloading filter driver is not safe!
	//

#if DBG
    DriverObject -> DriverUnload                                 = DriverUnload;
#endif

	fastIoDispatch = (PFAST_IO_DISPATCH) ExAllocatePool( NonPagedPool, sizeof(FAST_IO_DISPATCH) );
	if( fastIoDispatch == NULL )
	{
		KdPrint (("[-]Insufficient resources\n"));

        IoDeleteSymbolicLink (&gusDosDeviceName);
		IoDeleteDevice (gpdControl);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	fastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
    fastIoDispatch->FastIoCheckIfPossible = FsftFastIoCheckIfPossible;
    fastIoDispatch->FastIoRead = FsftFastIoRead;
    fastIoDispatch->FastIoWrite = FsftFastIoWrite;
    fastIoDispatch->FastIoQueryBasicInfo = FsftFastIoQueryBasicInfo;
    fastIoDispatch->FastIoQueryStandardInfo = FsftFastIoQueryStandardInfo;
    fastIoDispatch->FastIoLock = FsftFastIoLock;
    fastIoDispatch->FastIoUnlockSingle = FsftFastIoUnlockSingle;
    fastIoDispatch->FastIoUnlockAll = FsftFastIoUnlockAll;
    fastIoDispatch->FastIoUnlockAllByKey = FsftFastIoUnlockAllByKey;
    fastIoDispatch->FastIoDeviceControl = FsftFastIoDeviceControl;
    fastIoDispatch->FastIoDetachDevice = FsftFastIoDetachDevice;
    fastIoDispatch->FastIoQueryNetworkOpenInfo = FsftFastIoQueryNetworkOpenInfo;
    fastIoDispatch->AcquireForModWrite = FsftFastIoAcquireForModWrite;
    fastIoDispatch->MdlRead = FsftFastIoMdlRead;
    fastIoDispatch->MdlReadComplete = FsftFastIoMdlReadComplete;
    fastIoDispatch->PrepareMdlWrite = FsftFastIoPrepareMdlWrite;
    fastIoDispatch->MdlWriteComplete = FsftFastIoMdlWriteComplete;
    fastIoDispatch->FastIoReadCompressed = FsftFastIoReadCompressed;
    fastIoDispatch->FastIoWriteCompressed = FsftFastIoWriteCompressed;
    fastIoDispatch->MdlReadCompleteCompressed = FsftFastIoMdlReadCompleteCompressed;
    fastIoDispatch->MdlWriteCompleteCompressed = FsftFastIoMdlWriteCompleteCompressed;
    fastIoDispatch->FastIoQueryOpen = FsftFastIoQueryOpen;
    fastIoDispatch->ReleaseForModWrite = FsftFastIoReleaseForModWrite;
    fastIoDispatch->AcquireForCcFlush = FsftFastIoAcquireForCcFlush;
    fastIoDispatch->ReleaseForCcFlush = FsftFastIoReleaseForCcFlush;

    DriverObject -> FastIoDispatch = fastIoDispatch;

	//
	// Attach to device stack
	//

	PDEVICE_OBJECT AttachToDeviceObject;
	PFILE_OBJECT AttachToFileObject;
	HANDLE AttachToFileHandle;

	// Reference device object
	status = OpenDriveByLetter (
		AttachToName,
		&AttachToDeviceObject,
		&AttachToFileObject,
		&AttachToFileHandle );

	if( !NT_SUCCESS(status) )
	{
		KdPrint(("Can't reference device to attach to %S, staus: 0x%08x\n", AttachToName, status));
		IoDeleteSymbolicLink( &gusDosDeviceName );
		IoDeleteDevice( gpdControl );
		return STATUS_UNSUCCESSFUL;
	}

	// Create FiDO
    status = IoCreateDevice (
		DriverObject,
		sizeof (FILTER_DEVICE_EXTENSION),
		(PUNICODE_STRING) NULL,
		AttachToDeviceObject->DeviceType,
		0, // FILE_AUTOGENERATED_DEVICE_NAME,
        FALSE,
		&gpdFilterDeviceObject );

	if( !NT_SUCCESS(status) )
	{
		KdPrint(("Can't create attach device to attach to %S, status: 0x%08x\n", AttachToName, status));
		ObDereferenceObject( AttachToFileObject );
		ZwClose( AttachToFileHandle );
		IoDeleteSymbolicLink( &gusDosDeviceName );
		IoDeleteDevice( gpdControl );
		return STATUS_UNSUCCESSFUL;
	}

	PFILTER_DEVICE_EXTENSION DevExt = (PFILTER_DEVICE_EXTENSION) gpdFilterDeviceObject->DeviceExtension;

	// Attach to device stack safe
	status = IoAttachDeviceToDeviceStackSafe (
		gpdFilterDeviceObject,
		AttachToDeviceObject,
		&DevExt->AttachedToDeviceObject );

	if( !NT_SUCCESS(status) )
	{
		KdPrint(("Can't attach to %S, error: 0x%08x\n", AttachToName, status));
		IoDeleteDevice( gpdFilterDeviceObject );
		ObDereferenceObject( AttachToFileObject );
		ZwClose( AttachToFileHandle );
		IoDeleteSymbolicLink( &gusDosDeviceName );
		IoDeleteDevice( gpdControl );
		return STATUS_UNSUCCESSFUL;
	}

	// Dereference target device
	ObDereferenceObject( AttachToFileObject );
	ZwClose( AttachToFileHandle );

	KdPrint(("[+] Successfully attached to %S\n", AttachToName));

    return STATUS_SUCCESS;
}
