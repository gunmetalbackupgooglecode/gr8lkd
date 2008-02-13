//
// gr8 live kernel debugging driver (gr8lkdd)
//
// [C] Great, 2007. http://hellknights.void.ru/
//
// Посвящается ProTeuS'у в честь его дня рождения
//
// Fast I/O dispatchers
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


BOOLEAN
FsftFastIoCheckIfPossible(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoCheckIfPossible()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoCheckIfPossible )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoCheckIfPossible (
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			CheckForReadOperation,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoRead()\r\n"));

	if( EnableIrpFiltering &&
		FileObject &&
		FileObject->FileName.Buffer &&
		RtlCompareUnicodeString( &FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 )
	{
		IoStatus->Status = Read( FileObject, Buffer, Length, *FileOffset, &IoStatus->Information );
		KdPrint(("[+] FastIoRead: completed\n"));
		return TRUE;
	}

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoRead )
	{
		KdPrint(("[+] Chain call\r\n"));
		BOOLEAN ret = DestDriverObject->FastIoDispatch->FastIoRead (
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
		if( ret )
		{
			KdPrint(("[+] Processed: FastIoRead (Offset=%08x`%08x, Length=%08x)\n", FileOffset->HighPart, FileOffset->LowPart, Length));

			ULONG nBytes = 10;
			BYTE *Bytes = (BYTE*)ExAllocatePool( PagedPool, nBytes+1 );
			memcpy( Bytes, Buffer, nBytes );
			Bytes[nBytes] = 0;

			KdPrint(("[+] FastIo used, first %d bytes: '%s'\n", nBytes, Bytes ));
			ExFreePool( Bytes );
		}
		return ret;

	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoWrite()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoWrite )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoWrite (
			FileObject,
			FileOffset,
			Length,
			Wait,
			LockKey,
			Buffer,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoQueryBasicInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoQueryBasicInfo()\r\n"));

	if( EnableIrpFiltering &&
		FileObject &&
		FileObject->FileName.Buffer &&
		RtlCompareUnicodeString( &FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 )
	{
		FillBasicInfo( Buffer );
		IoStatus->Status = STATUS_SUCCESS;
		IoStatus->Information = sizeof(FILE_STANDARD_INFORMATION);
		KdPrint(("[+] FastIoQueryBasicInfo: filled\n"));
		return TRUE;
	}

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoQueryBasicInfo )
	{
		KdPrint(("[+] Chain call\r\n"));
		BOOLEAN ret = DestDriverObject->FastIoDispatch->FastIoQueryBasicInfo (
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );

		return ret;
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoQueryStandardInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoQueryStandardInfo()\r\n"));

	if( EnableIrpFiltering &&
		FileObject &&
		FileObject->FileName.Buffer &&
		RtlCompareUnicodeString( &FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 )
	{
		FillStandardInfo( Buffer );
		IoStatus->Status = STATUS_SUCCESS;
		IoStatus->Information = sizeof(FILE_STANDARD_INFORMATION);
		KdPrint(("[+] FastIoQueryStandardInfo: filled\n"));
		return TRUE;
	}

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoQueryStandardInfo )
	{
		KdPrint(("[+] Chain call\r\n"));
		BOOLEAN ret = DestDriverObject->FastIoDispatch->FastIoQueryStandardInfo (
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );

		return ret;
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoLock(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoLock()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoLock )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoLock (
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			FailImmediately,
			ExclusiveLock,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoUnlockSingle(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoUnlockSingle()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoUnlockSingle )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoUnlockSingle (
			FileObject,
			FileOffset,
			Length,
			ProcessId,
			Key,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoUnlockAll(
    IN PFILE_OBJECT FileObject,
    PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoUnlockAll()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoUnlockAll )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoUnlockAll (
			FileObject,
			ProcessId,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoUnlockAllByKey(
    IN PFILE_OBJECT FileObject,
    PVOID ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoUnlockAllByKey()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoUnlockAllByKey )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoUnlockAllByKey (
			FileObject,
			ProcessId,
			Key,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoDeviceControl(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if (DeviceObject == gpdControl)
    {
		KdPrint(("[~] CDO DeviceIoControl request\r\n"));

		PMDL Mdl = IoAllocateMdl( OutputBuffer, OutputBufferLength, 0, 0, 0 );

		__try {
			MmProbeAndLockPages( Mdl, UserMode, IoWriteAccess );
		}
		__except( EXCEPTION_EXECUTE_HANDLER )
		{
			IoStatus->Status = GetExceptionCode();
			return FALSE;
		}

		IoStatus->Status = CdoDeviceIoControl(
			IoControlCode,
			OutputBuffer,
			OutputBufferLength,
			&IoStatus->Information );

		MmUnlockPages( Mdl );
		IoFreeMdl( Mdl );

		return TRUE;
	}

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoDeviceControl()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoDeviceControl )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoDeviceControl (
			FileObject,
			Wait,
			InputBuffer,
			InputBufferLength,
			OutputBuffer,
			OutputBufferLength,
			IoControlCode,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

VOID
FsftFastIoDetachDevice(
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    )
{
	KdPrint(("[~] FsftFastIoDetachDevice()\r\n"));

    IoDetachDevice( TargetDevice );
    IoDeleteDevice( SourceDevice );
}

BOOLEAN
FsftFastIoQueryNetworkOpenInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoQueryNetworkOpenInfo()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoQueryNetworkOpenInfo )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoQueryNetworkOpenInfo (
			FileObject,
			Wait,
			Buffer,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

NTSTATUS
FsftFastIoAcquireForModWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER EndingOffset,
    OUT PERESOURCE *ResourceToRelease,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoAcquireForModWrite()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->AcquireForModWrite )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->AcquireForModWrite (
			FileObject,
			EndingOffset,
			ResourceToRelease,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return STATUS_NOT_IMPLEMENTED;
	}
}

BOOLEAN
FsftFastIoMdlRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoMdlRead()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->MdlRead )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->MdlRead (
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoMdlReadComplete(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoMdlReadComplete()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->MdlReadComplete )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->MdlReadComplete (
			FileObject,
			MdlChain,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoPrepareMdlWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoPrepareMdlWrite()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->PrepareMdlWrite )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->PrepareMdlWrite (
			FileObject,
			FileOffset,
			Length,
			LockKey,
			MdlChain,
			IoStatus,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoMdlWriteComplete(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoMdlWriteComplete()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->MdlWriteComplete )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->MdlWriteComplete (
			FileObject,
			FileOffset,
			MdlChain,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoReadCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT PCOMPRESSED_DATA_INFO CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoReadCompressed()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoReadCompressed )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoReadCompressed (
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoWriteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PCOMPRESSED_DATA_INFO CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoWriteCompressed()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoWriteCompressed )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->FastIoWriteCompressed (
			FileObject,
			FileOffset,
			Length,
			LockKey,
			Buffer,
			MdlChain,
			IoStatus,
			CompressedDataInfo,
			CompressedDataInfoLength,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoMdlReadCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoMdlReadCompleteCompressed()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->MdlReadCompleteCompressed )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->MdlReadCompleteCompressed (
			FileObject,
			MdlChain,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoMdlWriteCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoMdlWriteCompleteCompressed()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->MdlWriteCompleteCompressed )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->MdlWriteCompleteCompressed (
			FileObject,
			FileOffset,
			MdlChain,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

BOOLEAN
FsftFastIoQueryOpen(
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;
	PIO_STACK_LOCATION pisl = IoGetCurrentIrpStackLocation(Irp);

	KdPrint(("[~] FsftFastIoQueryOpen()\r\n"));

	if( EnableIrpFiltering &&
		pisl->FileObject &&
		pisl->FileObject->FileName.Buffer &&
		RtlCompareUnicodeString( &pisl->FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 )
	{
		NetworkInformation->AllocationSize.QuadPart = ALLOCATION_SIZE;
		NetworkInformation->EndOfFile = VirtualFile.Size;
		NetworkInformation->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;

		KeQuerySystemTime( &NetworkInformation->ChangeTime );
		KeQuerySystemTime( &NetworkInformation->LastWriteTime );
		KeQuerySystemTime( &NetworkInformation->LastAccessTime );
		KeQuerySystemTime( &NetworkInformation->CreationTime );

		KdPrint(("[+] FastIoQueryOpen: completed\n"));
		return TRUE;
	}

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->FastIoQueryOpen )
	{
		KdPrint(("[+] Chain call\r\n"));

		IoCopyCurrentIrpStackLocationToNext( Irp );
		IoSetCompletionRoutine( Irp, NULL, NULL, FALSE, FALSE, FALSE );

		PIO_STACK_LOCATION piNextsl = IoGetCurrentIrpStackLocation( Irp ); // next
		piNextsl->DeviceObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject;

        Irp->CurrentLocation--;
        Irp->Tail.Overlay.CurrentStackLocation--;

		return DestDriverObject->FastIoDispatch->FastIoQueryOpen (
			Irp,
			NetworkInformation,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return FALSE;
	}
}

NTSTATUS
FsftFastIoReleaseForModWrite(
    IN PFILE_OBJECT FileObject,
    IN PERESOURCE ResourceToRelease,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoReleaseForModWrite()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->ReleaseForModWrite )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->ReleaseForModWrite (
			FileObject,
			ResourceToRelease,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return STATUS_NOT_IMPLEMENTED;
	}
}

NTSTATUS
FsftFastIoAcquireForCcFlush(
    IN PFILE_OBJECT FileObject,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoAcquireForCcFlush()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->AcquireForCcFlush )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->AcquireForCcFlush (
			FileObject,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return STATUS_NOT_IMPLEMENTED;
	}
}

NTSTATUS
FsftFastIoReleaseForCcFlush(
    IN PFILE_OBJECT FileObject,
    IN PDEVICE_OBJECT DeviceObject
    )
{
	if( DeviceObject == gpdControl )
		return FALSE;

	PDRIVER_OBJECT DestDriverObject = ((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject->DriverObject;

	KdPrint(("[~] FsftFastIoReleaseForCcFlush()\r\n"));

	if( DestDriverObject->FastIoDispatch && DestDriverObject->FastIoDispatch->ReleaseForCcFlush )
	{
		KdPrint(("[+] Chain call\r\n"));
		return DestDriverObject->FastIoDispatch->ReleaseForCcFlush (
			FileObject,
			((PFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject );
	}
	else
	{
		KdPrint(("[-] Chain not present, returning FALSE\n"));
		return STATUS_NOT_IMPLEMENTED;
	}
}
