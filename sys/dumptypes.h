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

typedef struct _DUMP_HEADER {
/* 00 */    ULONG Signature;
/* 04 */    ULONG ValidDump;
/* 08 */    ULONG MajorVersion;
/* 0c */    ULONG MinorVersion;
/* 10 */    ULONG DirectoryTableBase;
/* 14 */    PULONG PfnDataBase;
/* 18 */    PLIST_ENTRY PsLoadedModuleList;
/* 1c */    PLIST_ENTRY PsActiveProcessHead;
/* 20 */    ULONG MachineImageType;
/* 24 */    ULONG NumberProcessors;
/* 28 */    ULONG BugCheckCode;
/* 2c */    ULONG BugCheckParameter1;
/* 30 */    ULONG BugCheckParameter2;
/* 34 */    ULONG BugCheckParameter3;
/* 38 */    ULONG BugCheckParameter4;
/* 3c */    CHAR VersionUser[32];
#if 0
/* 40 */    ULONG Spare1;
/* 44 */    ULONG Spare2;
/* 48 */    ULONG Unknown1;
/* 4c */    ULONG Unknown2;
/* 50 */    ULONG Unknown3;
/* 54 */    ULONG Unknown4;
/* 58 */    ULONG Unknown5;
#endif
/* 5c */    BYTE PaeEnabled;  BYTE Reserved3[3];
/* 60 */    PVOID KdDebuggerDataBlock;
} DUMP_HEADER, *PDUMP_HEADER;

// Data Blocks
#define DH_PHYSICAL_MEMORY_BLOCK        25
#define DH_CONTEXT_RECORD               200
#define DH_EXCEPTION_RECORD             500
#define DH_DUMP_TYPE					994
#define DH_CALLBACKS_STATUS             996
#define DH_PRODUCT_TYPE                 997
#define DH_SUITE_MASK                   998
#define	DH_REQUIRED_DUMP_SPACE			1000
#define DH_INTERRUPT_TIME               1006
#define DH_SYSTEM_TIME                  1008

#define DH_SUMMARY_DUMP_RECORD			1024

// Dump types
#define DUMP_TYPE_TRIAGE				4
#define DUMP_TYPE_SUMMARY				2
#define DUMP_TYPE_FULL					1

#define DUMP_MAJOR_FREE		0xF
#define DUMP_MAJOR_CHECKED	0xC

// Page frame number
typedef unsigned long PFN_NUMBER;

typedef struct _PHYSICAL_MEMORY_RUN {
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
} PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR {
    ULONG NumberOfRuns;
    PFN_NUMBER NumberOfPages;
    PHYSICAL_MEMORY_RUN Run[1];
} PHYSICAL_MEMORY_DESCRIPTOR, *PPHYSICAL_MEMORY_DESCRIPTOR;

// Bitmap
#define RtlCheckBit(BMH,BP) ((((BMH)->Buffer[(BP) / 32]) >> ((BP) % 32)) & 0x1)

template <class T>
struct PFUNC {
	T  VirtualAddress;
	ULONG  ZeroField;
};

typedef struct _KD_DEBUGGER_DATA_BLOCK {
	ULONG  Unknown1[4];
	ULONG  ValidBlock; // 'GBDK'
	ULONG  Size; // 0x290
	PFUNC<PVOID>  _imp__VidInitialize;
	PFUNC<PVOID>  RtlpBreakWithStatusInstruction;
	ULONG  Unknown2[4];
	PFUNC<PVOID>  KiCallUserMode;
	ULONG  Unknown3[2];
	PFUNC<PVOID>  PsLoadedModuleList;
	PFUNC<PVOID>  PsActiveProcessHead;
	PFUNC<PVOID>  PspCidTable;
	PFUNC<PVOID>  ExpSystemResourcesList;
	PFUNC<PVOID>  ExpPagedPoolDescriptor;
	PFUNC<PVOID>  ExpNumberOfPagedPools;
	PFUNC<PVOID>  KeTimeIncrement;
	PFUNC<PVOID>  KeBugCheckCallbackListHead;
	PFUNC<PVOID>  KiBugCheckData;
	PFUNC<PVOID>  IopErrorLogListHead;
	PFUNC<PVOID>  ObpRootDirectoryObject;
	PFUNC<PVOID>  ObpTypeObjectType;
	PFUNC<PVOID>  MmSystemCacheStart;
	PFUNC<PVOID>  MmSystemCacheEnd;
	PFUNC<PVOID>  MmSystemCacheWs;
	PFUNC<PVOID>  MmPfnDatabase;
	PFUNC<PVOID>  MmSystemPtesStart;
	PFUNC<PVOID>  MmSystemPtesEnd;
	PFUNC<PVOID>  MmSubsectionBase;
	PFUNC<PVOID>  MmNumberOfPagingFiles;
	PFUNC<PVOID>  MmLowestPhysicalPage;
	PFUNC<PVOID>  MmHighestPhysicalPage;
	PFUNC<PVOID>  MmNumberOfPhysicalPages;
	PFUNC<PVOID>  MmMaximumNonPagedPoolInBytes;
	PFUNC<PVOID>  MmNonPagedSystemStart;
	PFUNC<PVOID>  MmNonPagedPoolStart;
	PFUNC<PVOID>  MmNonPagedPoolEnd;
	PFUNC<PVOID>  MmPagedPoolStart;
	PFUNC<PVOID>  MmPagedPoolEnd;
	PFUNC<PVOID>  MmPagedPoolInfo;
	PFUNC<PVOID>  Unknown4;
	PFUNC<PVOID>  MmSizeOfPagedPoolInBytes;
	PFUNC<PVOID>  MmTotalCommitLimit;
	PFUNC<PVOID>  MmTotalCommittedPages;
	PFUNC<PVOID>  MmSharedCommit;
	PFUNC<PVOID>  MmDriverCommit;
	PFUNC<PVOID>  MmProcessCommit;
	PFUNC<PVOID>  MmPagedPoolCommit;
	PFUNC<PVOID>  Unknown5;
	PFUNC<PVOID>  MmZeroedPageListHead;
	PFUNC<PVOID>  MmFreePageListHead;
	PFUNC<PVOID>  MmStandbyPageListHead;
	PFUNC<PVOID>  MmModifiedPageListHead;
	PFUNC<PVOID>  MmModifiedNoWritePageListHead;
	PFUNC<PVOID>  MmAvailablePages;
	PFUNC<PVOID>  MmResidentAvailablePages;
	PFUNC<PVOID>  PoolTrackTable;
	PFUNC<PVOID>  NonPagedPoolDescriptor;
	PFUNC<PVOID>  MmHighestUserAddress;
	PFUNC<PVOID>  MmSystemRangeStart;
	PFUNC<PVOID>  MmUserProbeAddress;
	PFUNC<PVOID>  KdPrintCircularBuffer;
	PFUNC<PVOID>  KdPrintWritePointer;
	PFUNC<PVOID>  KdPrintWritePointer2;
	PFUNC<PVOID>  KdPrintRolloverCount;
	PFUNC<PVOID>  MmLoadedUserImageList;
	PFUNC<PVOID>  NtBuildLab;
	PFUNC<PVOID>  Unknown6;
	PFUNC<PVOID>  KiProcessorBlock;
	PFUNC<PVOID>  MmUnloadedDrivers;
	PFUNC<PVOID>  MmLastUnloadedDriver;
	PFUNC<PVOID>  MmTriageActionTaken;
	PFUNC<PVOID>  MmSpecialPoolTag;
	PFUNC<PVOID>  KernelVerifier;
	PFUNC<PVOID>  MmVerifierData;
	PFUNC<PVOID>  MmAllocateNonPagedPool;
	PFUNC<PVOID>  MmPeakCommitment;
	PFUNC<PVOID>  MmTotalCommitLimitMaximum;
	PFUNC<PVOID>  CmNtCSDVersion;
	PFUNC<PPHYSICAL_MEMORY_DESCRIPTOR*>  MmPhysicalMemoryBlock;
	PFUNC<PVOID>  MmSessionBase;
	PFUNC<PVOID>  MmSessionSize;
	PFUNC<PVOID>  Unknown7;

} KD_DEBUGGER_DATA_BLOCK, *PKD_DEBUGGER_DATA_BLOCK;

__inline ULONG CR4() {
	__asm __emit 0x0F
	__asm __emit 0x20
	__asm __emit 0xE0
}

__inline ULONG CR3() {
	__asm __emit 0x0F
	__asm __emit 0x20
	__asm __emit 0xD8
}

#define PAE_ENABLED  (1<<5)


