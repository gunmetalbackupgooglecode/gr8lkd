//
// gr8 live kernel debugging driver (gr8lkdd)
//
// [C] Great, 2007. http://hellknights.void.ru/
//
// Посвящается ProTeuS'у в честь его дня рождения
//
// IRP Dispatch routines
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

WCHAR*
DuplicateUnicodeStringZero(
	PUNICODE_STRING Input
	)
{
	if( !Input )
		return NULL;

	WCHAR* Out = (WCHAR*) ExAllocatePool( NonPagedPool, Input->Length + 2 );
	if( Out )
	{
		memcpy( Out, Input->Buffer, Input->Length );
		Out[ Input->Length/2 ] = 0;
	}
	return Out;
}

LONG NotCompletedIrpsCount = 0;

NTSTATUS
EditIrpCompletion(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context
    )
{
	PIO_STACK_LOCATION pisl = IoGetCurrentIrpStackLocation(Irp);

	if( pisl->MajorFunction != IRP_MJ_READ )
	{
		WCHAR *FileName = DuplicateUnicodeStringZero(&pisl->FileObject->FileName), *DisplayedFileName = L"(null)";

		if( FileName ) DisplayedFileName = FileName;

		KdPrint(("-->In IRP completion routine for %s, IRP completed (Status=%08x, Info=%08x) [FileName=%S Len=%d], RestNotCompletedIrps=%d\n",
			LookupConstDesc( IrpTypes, pisl->MajorFunction ),
			Irp->IoStatus.Status, Irp->IoStatus.Information,
			DisplayedFileName,
			pisl->FileObject->FileName.Length,
			NotCompletedIrpsCount-1
			));

		if( FileName) ExFreePool( FileName );

	}

	NTSTATUS Status = STATUS_SUCCESS;

	if( !NT_SUCCESS(Irp->IoStatus.Status) )
	{
		KdPrint(("Nothing to correct because of error status %08x\n", Irp->IoStatus.Status));
		Status = STATUS_SUCCESS;
		goto _exit;
	}

	// Check if it's request to virtual file.
	if( pisl->FileObject &&
		pisl->FileObject->FileName.Buffer &&
		( pisl->FileObject->FileName.Length & 1 ) == 0  &&
		RtlCompareUnicodeString( &pisl->FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 )
	{
		//
		// Switch IRP MajorFunction
		//

		if( pisl->MajorFunction == IRP_MJ_CREATE )
		{
			// не помогает, блядь
			//CcUninitializeCacheMap( pisl->FileObject, 0, 0 );
		}
	}
	else
	if( pisl->FileObject &&
		pisl->FileObject->FileName.Buffer &&
		( pisl->FileObject->FileName.Length & 1 ) == 0 &&
		RtlCompareUnicodeString( &pisl->FileObject->FileName, &VirtualFile.DirectoryName, TRUE ) == 0 &&
		pisl->MajorFunction == IRP_MJ_DIRECTORY_CONTROL )
	{
		//
		// Correct directory query info
		//

		if( pisl->MinorFunction == IRP_MN_QUERY_DIRECTORY  )
		{
			KdPrint(("[~] Correcting IRP_MJ_DIRECTORY_CONTROL: IRP_MN_QUERY_DIRECTORY\n"));
			
			PVOID Buffer = Irp->UserBuffer;
			ULONG Length = ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.Length;

			KdPrint(("Buffer: %08x, Length: %08x\n", Buffer, Length));

			WCHAR* FileName = DuplicateUnicodeStringZero( ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileName );
			if( FileName ) {
				KdPrint(("FileName: '%S'\n", FileName));
				ExFreePool( FileName );
			}
			else KdPrint(("FileName: (null)\n"));

			KdPrint(("FileInformationClass: %s(0x%x)\n",
				LookupConstDesc( FileInformationClass, ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileInformationClass ),
				((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileInformationClass ));
			KdPrint(("FileIndex: 0x%08x\n", ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileIndex));

			if( ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileInformationClass == FileBothDirectoryInformation )
			{
				//
				// Lock user buffer
				//

				PMDL Mdl = IoAllocateMdl( Buffer, Length, 0, 0, 0 );
				if( !Mdl )
				{
					Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					goto _exit;
				}

				__try {
					MmProbeAndLockPages( Mdl, UserMode, IoWriteAccess );
				}
				__except( 1 ) {
					KdPrint(("MmProbeAndLockPages(): exception %08x\n", GetExceptionCode()));
					Irp->IoStatus.Status = GetExceptionCode();
					goto _exit;
				}

				PFILE_BOTH_DIR_INFORMATION BothDirInfo = (PFILE_BOTH_DIR_INFORMATION) Buffer;

				// Our file
				if( ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileName &&
					RtlCompareUnicodeString( &VirtualFile.RawName, ((EXTENDED_IO_STACK_LOCATION*)pisl)->Parameters.QueryDirectory.FileName, TRUE ) == 0 )
				{
					KdPrint(("[+] Direct request to our file, corrected\n"));

					// Correct here
					BothDirInfo->EndOfFile = VirtualFile.Size;
					BothDirInfo->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;

					KeQuerySystemTime( &BothDirInfo->ChangeTime );
					KeQuerySystemTime( &BothDirInfo->LastWriteTime );
					KeQuerySystemTime( &BothDirInfo->LastAccessTime );
					KeQuerySystemTime( &BothDirInfo->CreationTime );
				}
				else
				{
					//
					// Directory Query
					//

					KdPrint(("[~] Request to directory, searching file\n"));

					// Find our entry and correct it
					do {

						// Check name
						UNICODE_STRING CheckName;

						CheckName.Length = (USHORT)BothDirInfo->FileNameLength;
						CheckName.MaximumLength = CheckName.Length;
						CheckName.Buffer = BothDirInfo->FileName;

						KdPrint((" []Entry.FileName: '%S'\n", BothDirInfo->FileName));

						if( RtlCompareUnicodeString( &CheckName, &VirtualFile.RawName, TRUE ) == 0 )
						{
							// Our file
							KdPrint(("[+] File found, corrected\n"));

							BothDirInfo->EndOfFile = VirtualFile.Size;
							BothDirInfo->FileAttributes = FILE_ATTRIBUTE_ARCHIVE;

							KeQuerySystemTime( &BothDirInfo->ChangeTime );
							KeQuerySystemTime( &BothDirInfo->LastWriteTime );
							KeQuerySystemTime( &BothDirInfo->LastAccessTime );
							KeQuerySystemTime( &BothDirInfo->CreationTime );

							break;
						}

						if( !BothDirInfo->NextEntryOffset )
							break;

						*(ULONG*)&BothDirInfo += BothDirInfo->NextEntryOffset;
					}
					while( true );
				}

				MmUnlockPages( Mdl );
				IoFreeMdl( Mdl );

			} // FileBothDirectoryInformation

		} // IRP_MN_QUERY_DIRECTORY

	} // IRP_MJ_DIRECTORY_CONTROL
	
_exit:
#if DBG
	InterlockedDecrement( &NotCompletedIrpsCount );
#endif
	return Status;
}

#define IOCTL_GR8LKDD_ENABLE_IRPS_FILTERING  CTL_CODE( FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_GR8LKDD_PASS_ALL_IRPS_DOWN     CTL_CODE( FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_GR8LKDD_QUERY_FILTERING_FLAG   CTL_CODE( FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS )

NTSTATUS
CdoDeviceIoControl(
	ULONG IoControlCode,
	PVOID SystemBuffer,
	ULONG OutputBufferLength,
	ULONG *Written
	)
{
	NTSTATUS status;

	KdPrint(("CdoDeviceIoControl(): IoControlCode = %08x\n", IoControlCode));

	if( IoControlCode == IOCTL_GR8LKDD_ENABLE_IRPS_FILTERING )
	{
		EnableIrpFiltering = TRUE;

		//
		// Create dump file
		//

		status = CreateDumpFile( );

		if( !NT_SUCCESS(status) )
		{
			KdPrint(("Failed to create dump file\n"));
			return status;
		}

		return STATUS_SUCCESS;
	}
	else if( IoControlCode == IOCTL_GR8LKDD_PASS_ALL_IRPS_DOWN )
	{
		EnableIrpFiltering = FALSE;
	
		status = DeleteDumpFile( );

		if( !NT_SUCCESS(status) )
		{
			KdPrint(("Failed to delete dump file\n"));
			return status;
		}

		return STATUS_SUCCESS;
	}
	else if( IoControlCode == IOCTL_GR8LKDD_QUERY_FILTERING_FLAG )
	{
		__try
		{
			*(BOOLEAN*)SystemBuffer = EnableIrpFiltering;
			*Written = 1;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			KdPrint(("CdoDeviceIoControl(): IOCTL_GR8LKDD_QUERY_FILTERING_FLAG: exception %08x\n", GetExceptionCode()));
			return GetExceptionCode();
		}
		return STATUS_SUCCESS;
	}

	return STATUS_INVALID_PARAMETER;
}

NTSTATUS
FsftFsDispatch (
    PDEVICE_OBJECT       pDeviceObject,
    PIRP                 pIrp)

{
    PFILTER_DEVICE_EXTENSION pDevExt = NULL;
	PIO_STACK_LOCATION pisl;
	pisl = IoGetCurrentIrpStackLocation( pIrp );

	if (pDeviceObject == gpdControl)
    {
		KdPrint(("[~] CDO request, MajorFunction=%s[0x%x]\r\n", LookupConstDesc( IrpTypes, pisl->MajorFunction ), pisl->MajorFunction));

		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = STATUS_SUCCESS;

		if( pisl->MajorFunction == IRP_MJ_DEVICE_CONTROL )
		{
			pIrp->IoStatus.Status = CdoDeviceIoControl(
				pisl->Parameters.DeviceIoControl.IoControlCode,
				pIrp->AssociatedIrp.SystemBuffer,
				pisl->Parameters.DeviceIoControl.OutputBufferLength,
				&pIrp->IoStatus.Information );
		}

        IoCompleteRequest (pIrp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }
    else
    {
		//
		// Pass IRP down if it's not our request
		//

		// Filtering disabled, pass all IRPs down
		if( !EnableIrpFiltering )
		{
			IoSkipCurrentIrpStackLocation( pIrp );

			pDevExt = (PFILTER_DEVICE_EXTENSION)pDeviceObject -> DeviceExtension;
			return IoCallDriver (pDevExt -> AttachedToDeviceObject, pIrp);
		}

		char *Extra = 0;

		if( pisl->MajorFunction != IRP_MJ_READ ) // for performance issues
		{
			if( pisl->FileObject &&
				pisl->FileObject->FileName.Buffer )
			{
				Extra = (char*) ExAllocatePool( PagedPool, 256 );
				WCHAR* FileName = DuplicateUnicodeStringZero( &pisl->FileObject->FileName );
				if( FileName ) {
					_snprintf( Extra, 256, "Filename=%S", FileName );
					ExFreePool (FileName);
				}
				else _snprintf( Extra, 256, "FileName=(null)" );
			}

			KdPrint(("[~] FiDO request, MajorFunction=%s[0x%x]. %s\r\n", LookupConstDesc( IrpTypes, pisl->MajorFunction ), pisl->MajorFunction, (Extra ? Extra : "") ));

			if( Extra )
			{
				ExFreePool( Extra );
			}
		}

		// Check if it's request to virtual file.
		if( pisl->FileObject &&
			pisl->FileObject->FileName.Buffer &&
			( RtlCompareUnicodeString( &pisl->FileObject->FileName, &VirtualFile.Name, TRUE ) == 0 ||
			  RtlCompareUnicodeString( &pisl->FileObject->FileName, &VirtualFile.RawName, TRUE ) == 0 ) )
		{
			NTSTATUS Status = STATUS_UNSUCCESSFUL;
			BOOLEAN CompleteHere = FALSE;

			pIrp->IoStatus.Information = 0;

			//
			// IRPs which we should complete here
			//

			switch( pisl->MajorFunction )
			{
			case IRP_MJ_CREATE:

				CompleteHere = FALSE;

				// не помогает
				pisl->FileObject->Flags |= ( FO_SYNCHRONOUS_IO | FO_WRITE_THROUGH );
				pisl->FileObject->Flags &= ~FO_CACHE_SUPPORTED;

				// Don't allow to delete!
				if( pisl->Parameters.Create.SecurityContext->DesiredAccess & DELETE )
				{
					CompleteHere = TRUE;
					Status = STATUS_ACCESS_DENIED;
				}

				break;

			case IRP_MJ_QUERY_INFORMATION:

				CompleteHere = TRUE;
				KdPrint(("[+] Processing IRP_MJ_QUERY_INFORMATION: %s(0x%x)\n",
					LookupConstDesc( FileInformationClass, pisl->Parameters.QueryFile.FileInformationClass ),
					pisl->Parameters.QueryFile.FileInformationClass ));

				switch( pisl->Parameters.QueryFile.FileInformationClass )
				{
				case FileAllInformation:
					{
						PFILE_ALL_INFORMATION AllInfo = (PFILE_ALL_INFORMATION) pIrp->AssociatedIrp.SystemBuffer;

						FillBasicInfo( &AllInfo->BasicInformation );
						FillStandardInfo( &AllInfo->StandardInformation );

						pIrp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION);
						pIrp->IoStatus.Status = STATUS_SUCCESS;
					
						break;
					}

				case FileBasicInformation:

					FillBasicInfo( (PFILE_BASIC_INFORMATION)pIrp->AssociatedIrp.SystemBuffer );
					pIrp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
					pIrp->IoStatus.Status = STATUS_SUCCESS;
					break;

				case FileStandardInformation:

					FillStandardInfo( (PFILE_STANDARD_INFORMATION)pIrp->AssociatedIrp.SystemBuffer );
					pIrp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
					pIrp->IoStatus.Status = STATUS_SUCCESS;
					break;

				default:

					KdPrint(("Unknown FileInformationClass!! passing down\n"));
					CompleteHere = FALSE;
				}

				Status = STATUS_SUCCESS;
				break;

			case IRP_MJ_READ:

				CompleteHere = TRUE;
				/*KdPrint(("[~] IRP_MJ_READ: Buffer: 0x%08x, UserBuffer: 0x%08x, Length: 0x%08x, Offset: 0x%08x\n",
					pIrp->AssociatedIrp.SystemBuffer,
					pIrp->UserBuffer,
					pisl->Parameters.Read.Length,
					pisl->Parameters.Read.ByteOffset.LowPart ));*/
				
				{
					PVOID Buffer = pIrp->AssociatedIrp.SystemBuffer;
					PMDL Mdl = 0;

					if( Buffer || pIrp->UserBuffer )
					{
						if( pDeviceObject->Flags & DO_BUFFERED_IO ) {
							//KdPrint(("Device supports buffered I/O\n"));
						} else {

							//KdPrint(("Device does not support buffered I/O, UserBuffer=0x%08x\n", pIrp->UserBuffer));
							Buffer = pIrp->UserBuffer;

							//
							// Lock user buffer
							//

							Mdl = IoAllocateMdl( Buffer, pisl->Parameters.Read.Length, 0, 0, 0 );

							if( !Mdl ) {
								Status = STATUS_ACCESS_VIOLATION;
								break;
							}

							__try {
								MmProbeAndLockPages( Mdl, UserMode, IoWriteAccess );
							}
							__except( 1 ) {
								KdPrint(("MmProbeAndLockPages(): exception %08x\n", GetExceptionCode()));
								Status = GetExceptionCode();
								IoFreeMdl( Mdl );
								break;
							}
						}

						if( Buffer )
							Status = Read( pisl->FileObject, Buffer, pisl->Parameters.Read.Length, pisl->Parameters.Read.ByteOffset, &pIrp->IoStatus.Information );
						else
							Status = STATUS_ACCESS_VIOLATION;

						pisl->Parameters.Read.ByteOffset.LowPart += pIrp->IoStatus.Information;
	                    
						if( Mdl )
						{
							MmUnlockPages( Mdl );
							IoFreeMdl( Mdl );
						}
					}
					else if( pIrp->MdlAddress != NULL )
					{
						/*if( pIrp->MdlAddress->MdlFlags & MDL_MAPPED_TO_SYSTEM_VA )
							KdPrint(("Mdl is mapped!\n"));
						else
							KdPrint(("Mdl is not mapped\n"));*/

						Status = Read(
							pisl->FileObject,
							MmGetSystemAddressForMdlSafe( pIrp->MdlAddress, NormalPagePriority ),
							pisl->Parameters.Read.Length,
							pisl->Parameters.Read.ByteOffset,
							&pIrp->IoStatus.Information );
					}
					else
					{
						Status = STATUS_INVALID_PARAMETER;
					}

					if( NT_SUCCESS(Status) )
					{
						// не помогает, блядь
						//CcPurgeCacheSection( pisl->FileObject->SectionObjectPointer, NULL, 0, 0 );
					}

					//KdPrint(("[+] IRP_MJ_READ: Finished (Status=0x%08x, Written:0x%08x)\n", Status, pIrp->IoStatus.Information));
				}
				break;

			case IRP_MJ_WRITE:

				CompleteHere = TRUE;
				Status = STATUS_ACCESS_DENIED;
				break;

			default:

				KdPrint(("[+] Default behaviour: IRP passed down (MajorFunction=%s, FileName=%S)\n", LookupConstDesc( IrpTypes, pisl->MajorFunction ),
					pisl->FileObject->FileName.Buffer));
			}

			//
			// Complete here
			//

			if( CompleteHere )
			{
				pIrp->IoStatus.Status = Status;
				IoCompleteRequest( pIrp, IO_NO_INCREMENT );
				return Status;
			}
		}

		//
		// Request should be passed down. Do it
		//

		NTSTATUS Status;

		if( pisl->MajorFunction == IRP_MJ_DIRECTORY_CONTROL )
		{
			IoCopyCurrentIrpStackLocationToNext( pIrp );
			IoSetCompletionRoutineEx( pDeviceObject, pIrp, EditIrpCompletion, NULL, TRUE, FALSE, FALSE );
#if DBG
			InterlockedIncrement( &NotCompletedIrpsCount );
#endif
		}
		else
		{
			IoSkipCurrentIrpStackLocation( pIrp );
		}

		pDevExt = (PFILTER_DEVICE_EXTENSION)pDeviceObject -> DeviceExtension;
		Status = IoCallDriver (pDevExt -> AttachedToDeviceObject, pIrp);

		return Status;
    }
}

