
#include "ntifs.h"
#include "wdmsec.h"
#include "ntstrsafe.h"

#include "pfdriver.hpp"


// TODO: convert to a direct io model: http://www.adp-gmbh.ch/win/misc/writing_devicedriver.html

#define PROCFILTER_DEVICE_NAME (L"\\Device\\ProcFilterDriver")
#define PROCFILTER_DOSDEVICE_NAME (L"\\DosDevices\\ProcFilterDriver")
#define MEMORY_TAG 'TFCP' // "PCFT"


extern "C" {
	DRIVER_INITIALIZE DriverEntry;
	VOID OnDriverUnload(IN PDRIVER_OBJECT pdo);
	VOID OnCreateProcessEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
	VOID OnCreateThread(IN HANDLE ProcessId, IN HANDLE ThreadId, IN BOOLEAN Create);
	VOID OnLoadImage(__in_opt PUNICODE_STRING FullImageName, __in HANDLE ProcessId, __in PIMAGE_INFO ImageInfo);
	VOID IoCancelReadRoutine(PDEVICE_OBJECT pdo, PIRP Irp);
}
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, OnDriverUnload)


//
// Represents expected user-land writes to kernel (scan results)
//
typedef struct pending_write PENDING_WRITE;
struct pending_write {
	LIST_ENTRY           entry;              // List entry in the list of pending writes
	DWORD                dwEventType;        // One of EVENTTYPE_Xxx
	HANDLE               hPid;               // Pid associated with the write
	HANDLE               hTid;               // Thread ID associated with the write, if any
	void                *lpImageBase;        // Base pointer associated with image load events
	bool                 bResponseReceived;  // Set when the response structure is filled in from userland
	PROCFILTER_RESPONSE  response;           // The scan response data filled in from userland
	KEVENT              *pkeCompletionEvent; // The completion event signalled when the response is received
};

//
// Represents pending reads from the kernel (process, thread, and image events)
//
typedef struct pending_read PENDING_READ;
struct pending_read {
	LIST_ENTRY            entry;          // List entry in the list of pending reads
	PROCFILTER_REQUEST    request;        // The kernel -> userland scan request data header
	const UNICODE_STRING *pImageFileName; // Associated image file name if present, otherwise NULL
};

//
// The driver-specific device context data shared. Use DcLock()/DcUnlock()
// before calling any other DcXxx functions or accessing members.
//
typedef struct device_context DEVICE_CONTEXT;
struct device_context {
	// The following two list entries are FIFO queues representing serialized process creation events
	bool                     bDeviceInUse;      // Whether or not a handle has been opened by the driver
	bool                     bDeviceConfigured; // Has the device been configured with DeviceIoControl yet?
	ULONG                    hDeviceOwnerPid;   // Process ID of who has the device handle open, so the driver never scans the service exe
	LIST_ENTRY               llPendingWrites;   // Process creation events that will result in a write to the driver
	LIST_ENTRY               llPendingReads;    // Process creation events that need to be read from the driver
	ULONG                    nInProgress;       // Number of in-progress scans in user-land
	PROCFILTER_CONFIGURATION config[1];         // configurables from userland
	struct {
		PIRP       pPendingReadIrp;             // Non-null when userland is blocked & waiting for a read operation to complete
		KSPIN_LOCK Lock;                        // The lock that protects data in the structure
		KIRQL      OldLevel;                    // Used when the lock is acquired
	} data[1];                                  // Device context meta-data
};


// Global deice object to be used by event notification callbacks
static PDEVICE_OBJECT g_pDeviceObject = NULL;

// Helper function to complete a pending read IRP with the IO Manager
static void CompleteReadIrp(PIRP pReadIrp, const PENDING_READ *prPendingRead);


//
// Convenience function to receive the device's extension data
//
static inline
DEVICE_CONTEXT*
GetDeviceContext(PDEVICE_OBJECT pDeviceObject)
{
	return (DEVICE_CONTEXT*)pDeviceObject->DeviceExtension;
}


//
// Initiailize the device extension
//
static
void
DcInit(DEVICE_CONTEXT *dc)
{
	RtlZeroMemory(dc, sizeof(DEVICE_CONTEXT));
	InitializeListHead(&dc->llPendingWrites);
	InitializeListHead(&dc->llPendingReads);
	KeInitializeSpinLock(&dc->data->Lock);
}


static
void
DcDestroy(DEVICE_CONTEXT *dc)
{
	UNREFERENCED_PARAMETER(dc);
	// Currently no further action needed here
}


static
void
DcLock(DEVICE_CONTEXT *dc)
{
	KeAcquireSpinLock(&dc->data->Lock, &dc->data->OldLevel);
}


static
void
DcUnlock(DEVICE_CONTEXT *dc)
{
	KeReleaseSpinLock(&dc->data->Lock, dc->data->OldLevel);
}


//
// Pop  the next pending read IRP if it exists, otherwise return NULL.
//
static
PIRP
DcGetPendingReadIrp(DEVICE_CONTEXT *dc)
{
	PIRP pReadIrp = NULL;
	if (dc->data->pPendingReadIrp) {
		pReadIrp = dc->data->pPendingReadIrp;
		dc->data->pPendingReadIrp = NULL;
		IoSetCancelRoutine(pReadIrp, NULL);
	}
	return pReadIrp;
}


static inline
DWORD
HandleToPid(HANDLE hPid)
{
	return ((ULONG_PTR)hPid) & 0xFFFFFFFF;
}


//
// Request a scan from the YARA service if the device is in use and block until
// a response is received
//
DECLARE_GLOBAL_CONST_UNICODE_STRING(g_EmptyString, L"");
static
bool
Event(DWORD EventType, PCUNICODE_STRING ImageFileName, HANDLE Pid, HANDLE ParentPid, HANDLE ThreadId, void *lpImageBase, PROCFILTER_RESPONSE *o_response)
{
	KdPrint(("Entering Event()\n"));

	bool rv = false;
	DEVICE_CONTEXT *dc = GetDeviceContext(g_pDeviceObject);
	
	// Build the scan request data
	PENDING_READ prPendingRead;
	RtlZeroMemory(&prPendingRead, sizeof(PENDING_READ));
	prPendingRead.request.dwEventType = EventType;
	prPendingRead.request.dwProcessId = HandleToPid(Pid);
	prPendingRead.request.dwThreadId = HandleToPid(ThreadId);
	prPendingRead.request.lpImageBase = lpImageBase;
	prPendingRead.request.dwParentProcessId = HandleToPid(ParentPid);
	prPendingRead.request.szFileName[0] = L'\0';
	prPendingRead.pImageFileName = ImageFileName;

	PENDING_WRITE pwPendingWrite;
	RtlZeroMemory(&pwPendingWrite, sizeof(PENDING_WRITE));

	KEVENT keWriteCompletionEvent;
	KeInitializeEvent(&keWriteCompletionEvent, NotificationEvent, FALSE);
	pwPendingWrite.pkeCompletionEvent = &keWriteCompletionEvent;
	pwPendingWrite.dwEventType = EventType;
	pwPendingWrite.hPid = Pid;
	pwPendingWrite.hTid = ThreadId;
	pwPendingWrite.lpImageBase = lpImageBase;

	// If running, atomically add the entry to the pending read/write list
	DcLock(dc);
	PIRP pReadIrp = NULL;
	bool bDeviceInUse = dc->bDeviceInUse;
	ULONG nInProgress = 0;
	if (bDeviceInUse) {
		// If there is a pending Read IRP retrieve it so it can be completed right now,
		// otherwise queue the scan request in the device context so it can be completed
		// next time the device is read from
		pReadIrp = DcGetPendingReadIrp(dc);
		if (pReadIrp) {
			dc->nInProgress += 1;
			nInProgress = dc->nInProgress;
		} else {
			InsertTailList(&dc->llPendingReads, &prPendingRead.entry);
		}

		// Always queue the scan response data
		InsertTailList(&dc->llPendingWrites, &pwPendingWrite.entry);
	}
	DcUnlock(dc);

	// Complete the pending read IRP if one was waiting
	if (pReadIrp) {
		KdPrint(("Event() completing read IRP\n"));
		CompleteReadIrp(pReadIrp, &prPendingRead);
		KdPrint(("Read IRP completed\n"));
	}

	// If the device was turned off, don't scan and just exit instead
	if (!bDeviceInUse) {
		// The device is not in use and the read/write data was not stored, so cleanup and exit
		KdPrint(("Device not in use\n"));
		goto cleanup;
	}

	// The read/writes were successfully added to the queues, wait on the write's completion event
	// since the write completion event being signalled implies the read was also completed

	KdPrint(("Waiting on user-land write: %u in progress...\n", nInProgress));
	KeWaitForSingleObject(&keWriteCompletionEvent, Executive, KernelMode, FALSE, NULL);
	KdPrint(("Received user-land write\n"));

	// Copy out the scan response that was filled in from userland
	if (pwPendingWrite.bResponseReceived) {
		if (o_response) RtlCopyMemory(o_response, &pwPendingWrite.response, sizeof(PROCFILTER_RESPONSE));

		rv = true;
	}
	
cleanup:
	return rv;
}


//
// Atomically shut down the device and complete (with failure) all pending read/writes
//
static
void
DcShutdownDevice(DEVICE_CONTEXT *dc)
{
	if (!dc->bDeviceInUse) return;

	dc->bDeviceInUse = false;
	dc->hDeviceOwnerPid = 0;
	dc->bDeviceConfigured = false;
	PLIST_ENTRY entry = NULL;
	while ((entry = RemoveHeadList(&dc->llPendingReads)) != &dc->llPendingReads) {
		PENDING_READ *prPendingRead = CONTAINING_RECORD(entry, PENDING_READ, entry);
		// Clean up the read event here; reads/writes are both blocked in Event()
		// on the write event, which is released by the next loop that signals write
		// events.  So no clean up here is needed; structure objects are released
		// when the threads blocking on Event() are freed in the below loop.
		UNREFERENCED_PARAMETER(prPendingRead);
	}
	while ((entry = RemoveHeadList(&dc->llPendingWrites)) != &dc->llPendingWrites) {
		if (dc->nInProgress > 0) dc->nInProgress -= 1;
		DcUnlock(dc);
		PENDING_WRITE *pwPendingWrite = CONTAINING_RECORD(entry, PENDING_WRITE, entry);
		pwPendingWrite->bResponseReceived = false;
		// Release waiting threads
		KeSetEvent(pwPendingWrite->pkeCompletionEvent, IO_NO_INCREMENT, FALSE);
		DcLock(dc);
	}

	// Pull out the pending IRP if one exists
	PIRP pPendingReadIrp = DcGetPendingReadIrp(dc);
	dc->nInProgress = 0;
	DcUnlock(dc);

	//
	// Fail the IRP
	//
	if (pPendingReadIrp) {
		pPendingReadIrp->IoStatus.Information = 0;
		pPendingReadIrp->IoStatus.Status = STATUS_INVALID_HANDLE;
		IoCompleteRequest(pPendingReadIrp, IO_NO_INCREMENT);
	}

	DcLock(dc);
}


//
// Allocate space for the specified processes image name.  Free the
// returned pointer with FreeProcessImageName() rather than ExFreePool()
// directly in case AllocProcessImageName()'s implementation changes.
//
static
bool
AllocProcessImageName(HANDLE ProcessId, PUNICODE_STRING *o_ImageName)
{
	bool rv = false;
	PUNICODE_STRING ImageFileName = NULL;
	PEPROCESS process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))) {
		// TODO: Is there a better way to locate the processes filename?
		// http://www.osronline.com/article.cfm?article=472
		// https://social.msdn.microsoft.com/Forums/en-US/b1434ac7-cffc-4d21-b722-04dfd30671ad/translate-nt-namespace-path-to-win32-namespace-path?forum=wdk
		if (NT_SUCCESS(SeLocateProcessImageName(process, &ImageFileName))) {
			*o_ImageName = ImageFileName;
			rv = true;
		}
		ObDereferenceObject(process);
	}

	return rv;
}


static
void
FreeProcessImageName(PUNICODE_STRING ImageName)
{
	ExFreePool(ImageName);
}


//
// Callback invoked by the kernel for each new process creation and termination event
//
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559951%28v=vs.85%29.aspx
//
DECLARE_GLOBAL_CONST_UNICODE_STRING(g_Null, L"*NULL*");
VOID
OnCreateProcessEx(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	// check that the device is in use and that the process causing the event is not the userland service
	DEVICE_CONTEXT *dc = GetDeviceContext(g_pDeviceObject);
	DcLock(dc);
	bool bDeviceInUse = dc->bDeviceInUse;
	HANDLE hDeviceOwnerPid = (HANDLE)dc->hDeviceOwnerPid;
	bool bDeviceConfigured = dc->bDeviceConfigured;
	DcUnlock(dc);
	if (!bDeviceInUse) {
		KdPrint(("Not scanning process 0x%p; user-land process is not using this driver (is the ProcFilter service running?)\n", ProcessId));	
		return;
	} else if (!bDeviceConfigured) {
		KdPrint(("Ignoring process creation/termination event; device not yet configured\n"));
		return;
	} else if (hDeviceOwnerPid == ProcessId) {
		KdPrint(("Ignoring request to scan process that has the YARA scan device open (0x%p)\n", ProcessId));
		return;
	} else if (CreateInfo && hDeviceOwnerPid != NULL && hDeviceOwnerPid == CreateInfo->CreatingThreadId.UniqueProcess) {
		// CreateInfo->ParentProcessId 1) can be specifeid by NtCreateProcess() and 2) is not guaranteed correct, so it is not tested for here.
		// see https://msdn.microsoft.com/en-us/library/windows/hardware/ff559960%28v=vs.85%29.aspx and 
		// http://www.osronline.com/showThread.cfm?link=90946 for official documentation and discussion. Pids can be reused, but checking
		// against device owner pid is okay here since the driver is only open during the life of the opening process -- once the opening process
		// exits, the device is no longer in use which precludes this check from being done.
		//
		// The test for the parent pid here prevents a situation in which procfilter.exe creates a process and then deadlocks while waiting
		// for it to be created since that requires recursive entry into the procfilter core.
		KdPrint(("Ignoring request to scan process created by YARA device owner (0x%p)\n", ProcessId));
		return;
	}
	
	// Get the processes image name; dont use CreateInfo->ImageFileName since during termination this name is not available.
	// CreateInfo->ImageFileName contains a Dos-style drive letter and during termination there is no documented way
	// to acquire this same path name, so rather than using it we use AllocProcessImageName() which should give consistent
	// results, that way the user-land service gets the same image file name during creation and termination events.
	PUNICODE_STRING AllocatedImageFileName = NULL;
	if (!AllocProcessImageName(ProcessId, &AllocatedImageFileName)) {
		KdPrint(("Error acquiring process name for process 0x%p %wZ\n",
			ProcessId, (CreateInfo && CreateInfo->FileOpenNameAvailable) ? CreateInfo->ImageFileName : &g_Null));
		return;
	}
	PCUNICODE_STRING ImageFileName = AllocatedImageFileName;
	
	// Perform a scan with the userland service and handle the response accordingly
	// CreateInfo documentation: https://msdn.microsoft.com/en-us/library/windows/hardware/ff559960%28v=vs.85%29.aspx
	if (CreateInfo) { // a process is being created
		KdPrint(("New process: 0x%p %wZ\n", ProcessId, ImageFileName));
		PROCFILTER_RESPONSE response;
		RtlZeroMemory(&response, sizeof(PROCFILTER_RESPONSE));
		if (Event(EVENTTYPE_PROCESSCREATE, ImageFileName, ProcessId, CreateInfo->ParentProcessId, NULL, NULL, &response)) {
			KdPrint(("New process scanned: 0x%p %wZ\n", ProcessId, ImageFileName));
			// Scan successsful; allow/deny process creation based on scan results
			if (response.bBlock) {
				CreateInfo->CreationStatus = STATUS_VIRUS_INFECTED;
			}
		} else {
			KdPrint(("New process scan failed: 0x%p %wZ\n", ProcessId, ImageFileName));
			// Scan failed, deny or allow the process based on configuration
			if (dc->config->bDenyProcessCreationOnFailedScan) {
				CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
			}
		}
	} else { // A process is terminating
		KdPrint(("Process exiting: 0x%p %wZ\n", ProcessId, ImageFileName));
		
		if (Event(EVENTTYPE_PROCESSTERMINATE, ImageFileName, ProcessId, NULL, NULL, NULL, NULL)) {
			KdPrint(("Terminating process scanned: 0x%p %wZ\n", ProcessId, ImageFileName));
		} else {
			KdPrint(("Terminating process scan failed: 0x%p %wZ\n", ProcessId, ImageFileName));
		}
	}

	// Log the scan event for debugging purposes
	KdPrint(("ProcFilter(CI:%wZ/IFN:%wZ): Type:%s CreationStatus:%d\n",
				CreateInfo ? CreateInfo->ImageFileName : &g_Null,
				ImageFileName,
				CreateInfo ? "Create" : "Terminate", 
				CreateInfo ? CreateInfo->CreationStatus : STATUS_SUCCESS
				));

	// Cleanup
	FreeProcessImageName(AllocatedImageFileName);
}


//
// Thread creation/terminate notification callback
//
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559954%28v=vs.85%29.aspx
//
VOID
OnCreateThread(IN HANDLE ProcessId, IN HANDLE ThreadId, IN BOOLEAN Create)
{
	DEVICE_CONTEXT *dc = GetDeviceContext(g_pDeviceObject);
	DcLock(dc);
	bool bDeviceInUse = dc->bDeviceInUse;
	HANDLE hDeviceOwnerPid = (HANDLE)dc->hDeviceOwnerPid;
	bool bDeviceConfigured = dc->bDeviceConfigured;
	bool bWantThreadEvents = dc->config->bWantThreadEvents;
	DcUnlock(dc);
	if (!bDeviceInUse) {
		KdPrint(("Not scanning thread 0x%p in process 0x%p; user-land process is not using this driver (is the ProcFilter service running?)\n", ThreadId, ProcessId));	
		return;
	} else if (!bDeviceConfigured) {
		KdPrint(("Ignoring thread creation event; device not yet configured\n"));
		return;
	} else if (hDeviceOwnerPid == ProcessId) {
		KdPrint(("Ignoring thread event related to the process that has the YARA scan device open (0x%p)\n", ProcessId));
		return;
	} else if (!bWantThreadEvents) {
		return;
	}
	
	Event(Create ? EVENTTYPE_THREADCREATE : EVENTTYPE_THREADTERMINATE, NULL, ProcessId, Create ? PsGetCurrentProcessId() : NULL, ThreadId, NULL, NULL);
}


//
// Image load notification callback
//
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559957%28v=vs.85%29.aspx
//
DECLARE_GLOBAL_CONST_UNICODE_STRING(g_Unknown, L"*UNKNOWN*");
VOID
OnLoadImage(__in_opt PUNICODE_STRING PartialImageName, __in HANDLE  ProcessId, __in PIMAGE_INFO  ImageInfo)
{	
	KdPrint(("OnLoadImage() entered\n"));

	DEVICE_CONTEXT *dc = GetDeviceContext(g_pDeviceObject);
	DcLock(dc);
	bool bDeviceInUse = dc->bDeviceInUse;
	HANDLE hDeviceOwnerPid = (HANDLE)dc->hDeviceOwnerPid;
	bool bDeviceConfigured = dc->bDeviceConfigured;
	bool bWantImageLoadEvents = dc->config->bWantImageLoadEvents;
	DcUnlock(dc);
	if (!bDeviceInUse) {
		KdPrint(("Not processing image load in process 0x%p; user-land process is not using this driver (is the ProcFilter service running?)\n", ProcessId));	
		return;
	} else if (!ProcessId) {
		KdPrint(("Ignoring image load event for kernel module\n"));
		return;
	} else if (!bDeviceConfigured) {
		KdPrint(("Ignoring image load event; device not yet configured\n"));
		return;
	} else if (hDeviceOwnerPid == ProcessId) {
		KdPrint(("Ignoring image load event related to the process that has the YARA scan device open (0x%p)\n", ProcessId));
		return;
	} else if (!bWantImageLoadEvents) {
		return;
	}

	//
	// 'PartialImageName', or 'FullImageName' as MSDN documentation specifies, only includes a drive-
	// relative path and does not include the device from which the file exists on.
	//
	// ObQueryNameString() crashes due to some kind of race condition due to special kernel APCs being
	// disabled during this call on Windows 7, Windows Server 2008 R2 and below because they are
	// invoked while the kernel is holding a lock.
	//
	// On susceptible systems ObNameQueryString() is invoked, returns successfully, exports the event to
	// userland, gets the result, returns from the image load notification callback, then crashes afterwards
	// later on in the kernel 'somewhere'.
	//
	// Windows 10: Apcs disabled, Kernel apcs enabled, ObQueryString() does not crash
	// Windows 7: Apcs disabled, Kernel apcs disabled (leads to crash if ObQueryNameString() is called)
	//
	// So, generate an event with the full image name when possible, otherwise just use the 'PartialImageName' parameter
	//
	KdPrint(("OnLoadImage(): IRQL:%d ApcsDisabled:%d AllApcsDisabled:%d\n", KeGetCurrentIrql(), KeAreApcsDisabled(), KeAreAllApcsDisabled()));
	if (!KeAreAllApcsDisabled() && ImageInfo->ExtendedInfoPresent) {
		void *HeapPointer = NULL;
		IMAGE_INFO_EX *ImageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
		if (ImageInfoEx->FileObject) {
			unsigned char StackBuffer[1024];
			ULONG Length = sizeof(StackBuffer);
			OBJECT_NAME_INFORMATION *pObjectNameInfo = (OBJECT_NAME_INFORMATION*)StackBuffer;
			KdPrint(("Calling ObQueryNameString(): IRQL: %d\n", KeGetCurrentIrql()));
			//
			// Crash problem is described here: http://www.osronline.com/showThread.cfm?link=124110
			//
			// If APCs are disabled during this call (which they are if the kernel holds a lock which it
			// does in windows 7 and windows server 2008 r2 or less) then the IRP stack can get corrupted if
			// called functions use IRPs internally (this one does)
			//
			NTSTATUS rc = ObQueryNameString(ImageInfoEx->FileObject, pObjectNameInfo, Length, &Length);
			if (rc == STATUS_INFO_LENGTH_MISMATCH && Length > 0) {
				KdPrint(("Allocating heap memory\n"));
				HeapPointer = ExAllocatePoolWithTag(NonPagedPool, Length, MEMORY_TAG);
				if (HeapPointer) {
					pObjectNameInfo = (OBJECT_NAME_INFORMATION*)HeapPointer;
					rc = ObQueryNameString(ImageInfoEx->FileObject, pObjectNameInfo, Length, &Length);
				}
			}

			if (rc == STATUS_SUCCESS && pObjectNameInfo->Name.Buffer) {
				KdPrint(("Sending Image load event to userspace\n"));
				Event(EVENTTYPE_IMAGELOAD, &pObjectNameInfo->Name, ProcessId, NULL, NULL, ImageInfo->ImageBase, NULL);
				KdPrint(("Userspace image load event returned\n"));
			}
		}
	} else if (PartialImageName) {
		// Generate an event that only includes the partial file name
		Event(EVENTTYPE_IMAGELOAD, PartialImageName, ProcessId, NULL, NULL, ImageInfo->ImageBase, NULL);
	}
	
	KdPrint(("OnLoadImage() exited\n"));
}


//
// Handler for unimplemented IRPs
//
static
NTSTATUS
IrpUnsupported(IN PDEVICE_OBJECT pdo, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(pdo);
	UNREFERENCED_PARAMETER(Irp);

	return STATUS_NOT_SUPPORTED;
}


//
// Open the device
//
static
NTSTATUS
IrpMjCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);

	ULONG hDeviceOwnerPid = IoGetRequestorProcessId(Irp);
	// Dont allow more than one device to be opened at a time
	bool bOpened = false;
	DcLock(dc);
	if (!dc->bDeviceInUse) {
		dc->bDeviceInUse = true;
		dc->hDeviceOwnerPid = hDeviceOwnerPid;
		bOpened = true;
	}
	DcUnlock(dc);

	if (bOpened) {
		KdPrint(("Opened device: Owner Pid: 0x%08X\n", hDeviceOwnerPid));
	}

	NTSTATUS rc = bOpened ? STATUS_SUCCESS : STATUS_SHARING_VIOLATION;

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = rc;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return rc;
}


//
// Close the device
//
static
NTSTATUS
IrpMjClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);
	DcLock(dc);
	DcShutdownDevice(dc);
	DcUnlock(dc);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//
// Close the device
//
static
NTSTATUS
IrpMjShutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);
	DcLock(dc);
	DcShutdownDevice(dc);
	DcUnlock(dc);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


//
// Handle a configuration request from userland
//
static
NTSTATUS
IrpMjDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	KdPrint(("IrpMjDeviceControl(): Handling call\n"));
	
	ULONG_PTR Information = 0;
	NTSTATUS rc = STATUS_INVALID_PARAMETER;

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
	if (IrpSp && IrpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_PROCFILTER_CONFIGURE) {

		PVOID Buffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG BufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

		if (Buffer && BufferLength == sizeof(PROCFILTER_CONFIGURATION)) {
			KdPrint(("IrpMjDeviceControl(): Configuring device\n"));
			DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);
			DcLock(dc);
			bool bAlreadyConfigured = dc->bDeviceConfigured;
			bool bDeviceConfigured = false;
			if (!bAlreadyConfigured) {
				// store the procfilter configuration to the device context
				RtlCopyMemory(dc->config, Buffer, sizeof(PROCFILTER_CONFIGURATION));
				if (dc->config->dwProcFilterRequestSize == sizeof(PROCFILTER_REQUEST) && dc->config->dwProcMaxFilterRequestSize == PROCFILTER_REQUEST_SIZE) {
					dc->bDeviceConfigured = true;
					bDeviceConfigured = true;
				}
			}
			DcUnlock(dc);
			
			if (!bAlreadyConfigured && bDeviceConfigured) {
				rc = STATUS_SUCCESS;
			} else {
				rc = STATUS_UNSUCCESSFUL;
			}
		}
	}

	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = rc;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return rc;
}


static const char* const g_EventNames[NUM_EVENTTYPES] = {
	"None",
	"ProcessCreate",
	"ProcessTerminate",
	"ThreadCreate",
	"ThreadTerminate",
	"ImageLoad"
};

//
// Complete the given read IRP with the data from the PENDING_READ structure
//
static
void
CompleteReadIrp(PIRP pReadIrp, const PENDING_READ *prPendingRead)
{
	PROCFILTER_REQUEST *umRequest = (PROCFILTER_REQUEST*)pReadIrp->AssociatedIrp.SystemBuffer;
	RtlCopyMemory(umRequest, &prPendingRead->request, sizeof(PROCFILTER_REQUEST));
	ULONG dwRequestSize = sizeof(PROCFILTER_REQUEST);
	if (prPendingRead->pImageFileName && prPendingRead->pImageFileName->Buffer) {
		ULONG dwExtraCharacters = 0; // does not include the trailing null
		RtlCopyMemory(&umRequest->szFileName[dwExtraCharacters], L"\\\\?\\GLOBALROOT", 14 * sizeof(WCHAR));
		dwExtraCharacters += 14;
		RtlCopyMemory(&umRequest->szFileName[dwExtraCharacters], prPendingRead->pImageFileName->Buffer, prPendingRead->pImageFileName->Length);
		dwExtraCharacters += prPendingRead->pImageFileName->Length / sizeof(WCHAR);
		umRequest->szFileName[dwExtraCharacters] = L'\0';
		// Do not increment string length here since the header already contains room for the trailing NULL
		
		dwRequestSize += dwExtraCharacters * sizeof(WCHAR);
	}
	umRequest->dwRequestSize = dwRequestSize;

	KdPrint(("Read IRP Completion Driver->Service: %hs(%p/%wZ) sending %u bytes at %p to userspace\n",
		g_EventNames[prPendingRead->request.dwEventType] ? g_EventNames[prPendingRead->request.dwEventType] : "Unknown", prPendingRead->request.dwProcessId,
		(prPendingRead->pImageFileName && prPendingRead->pImageFileName->Buffer) ? prPendingRead->pImageFileName : &g_Null, dwRequestSize, &prPendingRead->request));

	if (dwRequestSize < sizeof(PROCFILTER_REQUEST)) KeBugCheck(DRIVER_VIOLATION);
	if (dwRequestSize > PROCFILTER_REQUEST_SIZE) KeBugCheck(DRIVER_OVERRAN_STACK_BUFFER);

	pReadIrp->IoStatus.Information = dwRequestSize;
	pReadIrp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(pReadIrp, IO_NO_INCREMENT);
}


//
// Read event received from userland
//
static
NTSTATUS
IrpMjRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS rc = STATUS_SUCCESS;
	ULONG_PTR dwBytesRead = 0;

	DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);
	
	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if (pIoStackIrp) {
		PVOID pBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG ulBufferSize = pIoStackIrp->Parameters.Read.Length;

		// Verify the arguments passed to ReadFile() are valid
		if (pBuffer && ulBufferSize == PROCFILTER_REQUEST_SIZE) {
			PENDING_READ *prPendingRead = NULL;

			DcLock(dc);
			if (dc->bDeviceInUse) {
				PLIST_ENTRY entry = RemoveHeadList(&dc->llPendingReads);
				if (entry != &dc->llPendingReads) {
					prPendingRead = CONTAINING_RECORD(entry, PENDING_READ, entry);
					dc->nInProgress += 1;
				} else {
					// No pending data available
					if (!dc->data->pPendingReadIrp) { // No read IRP queued, put it in the queue
						// Call IoMarkIrpPending() before queueing the IRP to avoid a condition where it is
						// dequeued and completed before it is marked pending
						IoSetCancelRoutine(Irp, IoCancelReadRoutine);
						IoMarkIrpPending(Irp);
						dc->data->pPendingReadIrp = Irp;
						//  The IRP has been stored for completion later
						KdPrint(("Marking Read IRP as STATUS_PENDING\n"));
						rc = STATUS_PENDING;
					} else {
						// Received a read while another read was already in-progress & blocking
						KdPrint(("IrpMjRead(): Occurred out of sequence\n"));
						rc = STATUS_REQUEST_OUT_OF_SEQUENCE;
					}
				}
			} else {
				rc = STATUS_DEVICE_NOT_CONNECTED;
			}
			DcUnlock(dc);

			if (prPendingRead)  {
				// If there is pending read data, complete it immediately
				// there was data waiting to be read, copy it out and complete the IRP
				CompleteReadIrp(Irp, prPendingRead);
				return STATUS_SUCCESS;
			}
		} else {
			KdPrint(("Invalid buffer and/or size sent to driver during a read operation\n"));
			rc = STATUS_INVALID_PARAMETER;
		}
	}
	
	Irp->IoStatus.Information = dwBytesRead;
	Irp->IoStatus.Status = rc;

	if (rc != STATUS_PENDING) {
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return rc;
}


//
// Write event received from userland
//
static
NTSTATUS
IrpMjWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	KdPrint(("IrpMjWrite() called\n"));

	NTSTATUS rc = STATUS_SUCCESS;
	ULONG_PTR dwBytesWritten = 0;

	DEVICE_CONTEXT *dc = GetDeviceContext(DeviceObject);

	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if (pIoStackIrp) {
		// Ensure buffer sizes are valid
		PVOID pBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG ulBufferSize = pIoStackIrp->Parameters.Write.Length;
		if (pBuffer && ulBufferSize == sizeof(PROCFILTER_RESPONSE)) {
			// Get the next write in queue to be completed

			PROCFILTER_RESPONSE *response = (PROCFILTER_RESPONSE*)pBuffer;
			
			DcLock(dc);
			PLIST_ENTRY entry = NULL;
			bool bDeviceInUse = dc->bDeviceInUse;
			if (bDeviceInUse) {
				// Find the pending write in the list, only searching back the number of outstanding reqeusts
				PLIST_ENTRY current = dc->llPendingWrites.Flink;
				ULONG i = 0;
				while (current != &dc->llPendingWrites && i < dc->nInProgress) {
					PENDING_WRITE *pwrite = CONTAINING_RECORD(current, PENDING_WRITE, entry);

					// Search the current entry to see if it pertains to the data being received
					if (pwrite->dwEventType == response->dwEventType) {
						bool bRemove = false;

						if (pwrite->dwEventType == EVENTTYPE_PROCESSCREATE || pwrite->dwEventType == EVENTTYPE_PROCESSTERMINATE) {
							if (HandleToPid(pwrite->hPid) == response->dwProcessId) bRemove = true;
						} else if (pwrite->dwEventType == EVENTTYPE_THREADCREATE || pwrite->dwEventType == EVENTTYPE_THREADTERMINATE) {
							if (HandleToPid(pwrite->hPid) == response->dwProcessId && HandleToPid(pwrite->hTid) == response->dwThreadId) bRemove = true;
						} else if (pwrite->dwEventType == EVENTTYPE_IMAGELOAD) {
							if (HandleToPid(pwrite->hPid) == response->dwProcessId && pwrite->lpImageBase == response->lpImageBase) bRemove = true;
						}

						if (bRemove) {
							RemoveEntryList(current);
							entry = current;
							dc->nInProgress -= 1;
							break;
						}
					}

					current = current->Flink;
					++i;
				}
			}
			DcUnlock(dc);

			if (!bDeviceInUse) {
				// There was no write in queue since the device is off
				rc = STATUS_PIPE_NOT_AVAILABLE;
			} else if (entry) {
				// A corresponding pending write was found, complete it 
				PENDING_WRITE *pwrite = CONTAINING_RECORD(entry, PENDING_WRITE, entry);
				pwrite->bResponseReceived = true;
				RtlCopyMemory(&pwrite->response, response, sizeof(PROCFILTER_RESPONSE));
				KeSetEvent(pwrite->pkeCompletionEvent, IO_NO_INCREMENT, FALSE);
				dwBytesWritten = sizeof(PROCFILTER_RESPONSE);
				KdPrint(("Completing IRP\n"));
				rc = STATUS_SUCCESS;
			} else {
				// The write was not found
				KdPrint(("Received out of sequence request for PID (%d, %d, %d, %d)\n",
					response->dwEventType, response->dwProcessId, response->dwThreadId, response->lpImageBase));
				KdBreakPoint();
				rc = STATUS_REQUEST_OUT_OF_SEQUENCE;
			}
		} else {
			KdPrint(("Invalid buffer and/or size sent to driver during a write operation\n"));
			rc = STATUS_INVALID_PARAMETER;
		}
	}

	Irp->IoStatus.Information = dwBytesWritten;
	Irp->IoStatus.Status = rc;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return rc;
}


//
// Invoked when a pending read is cancelled
//
VOID
IoCancelReadRoutine(PDEVICE_OBJECT pdo, PIRP Irp)
{
	KIRQL cancelIrql = Irp->CancelIrql;
	IoReleaseCancelSpinLock(cancelIrql);

	DEVICE_CONTEXT *dc = GetDeviceContext(pdo);
	DcLock(dc);
	if (dc->data->pPendingReadIrp == Irp) {
		dc->data->pPendingReadIrp = NULL;
	}
	DcUnlock(dc);

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_CANCELLED;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}


NTSTATUS
DriverEntry(IN PDRIVER_OBJECT pdo, IN PUNICODE_STRING pusRegistryPath)
{
	UNREFERENCED_PARAMETER(pusRegistryPath);

	KdPrint(("\nEntering YARA Scan Driver (Compiled %s %s)\n", __DATE__, __TIME__));
	
	//
	// Create the device object
	//
	UNICODE_STRING usDeviceName;
	RtlInitUnicodeString(&usDeviceName, PROCFILTER_DEVICE_NAME);
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS rc = IoCreateDeviceSecure(pdo, sizeof(DEVICE_CONTEXT), &usDeviceName, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL, NULL, &pDeviceObject);
	if (rc != STATUS_SUCCESS) {
		KdPrint(("Error creating ProcFilter Device Object\n"));
		return rc;
	}

	//
	// Create a symbolic link in DosDevices
	//
	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, PROCFILTER_DOSDEVICE_NAME);
	rc = IoCreateSymbolicLink(&usDosDeviceName, &usDeviceName);
	if (rc != STATUS_SUCCESS) {
		KdPrint(("Error creating ProcFilter DOS Device Object\n"));
		IoDeleteDevice(pDeviceObject);
		return rc;
	}

	//
	// Initialize device context
	//
	DEVICE_CONTEXT *dc = GetDeviceContext(pDeviceObject);
	DcInit(dc);

	__try {
		//
		// Initialize driver callbacks
		//
		for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; ++i) {
			pdo->MajorFunction[i] = IrpUnsupported;
		}
		pdo->DriverUnload = OnDriverUnload;
		pdo->MajorFunction[IRP_MJ_CREATE] = IrpMjCreate;
		pdo->MajorFunction[IRP_MJ_CLOSE] = IrpMjClose;
		pdo->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpMjDeviceControl;
		pdo->MajorFunction[IRP_MJ_READ] = IrpMjRead;
		pdo->MajorFunction[IRP_MJ_WRITE] = IrpMjWrite;
		pdo->MajorFunction[IRP_MJ_SHUTDOWN] = IrpMjShutdown;
		IoRegisterShutdownNotification(pDeviceObject);

		pDeviceObject->Flags |= DO_BUFFERED_IO;

		//
		// Place process creation, thread creation, and image load hooks or clean up and remove
		// if any hook installation fails
		//
		if ((rc = PsSetCreateProcessNotifyRoutineEx(OnCreateProcessEx, FALSE)) != STATUS_SUCCESS) {
			if (rc == STATUS_ACCESS_DENIED) {
				// Project Properties -> Linker -> All Options then add /INTEGRITYCHECK
				// See: https://www.osronline.com/showthread.cfm?link=169632
				// See: https://msdn.microsoft.com/en-us/library/dn195769.aspx?f=255&MSPPError=-2147217396
				KdPrint(("PsSetCreateProcessNotifyRoutineEx() failed; ensure /INTEGRITYCHECK linker flag was used during linking\n"));
			} else {
				KdPrint(("Unable to add process creation notification routine\n"));
			}
		} else if ((rc = PsSetCreateThreadNotifyRoutine(OnCreateThread)) != STATUS_SUCCESS) {
			PsSetCreateProcessNotifyRoutineEx(OnCreateProcessEx, TRUE);
			KdPrint(("Unable to add thread creation notification routine\n"));
		} else if ((rc = PsSetLoadImageNotifyRoutine(OnLoadImage)) != STATUS_SUCCESS) {
			PsSetCreateProcessNotifyRoutineEx(OnCreateProcessEx, TRUE);
			PsRemoveCreateThreadNotifyRoutine(OnCreateThread);
			KdPrint(("Unable to add image load notification routine\n"));
		} else {
			// All hook placement succeeded, set the return code to STATUS_SUCCESS, which it already is but only by coincidence
			// of the prior assignment.  Explicit set is clearer and expresses intent.
			KdPrint(("Added create process, create thread, and image load notification routines\n"));
			rc = STATUS_SUCCESS;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		KdPrint(("Exception encountered during driver initialization\n"));
		rc = STATUS_NONCONTINUABLE_EXCEPTION;
	}

	//
	// Either finish init-related tasks or cleanup based on success
	//
	if (rc == STATUS_SUCCESS) {
		g_pDeviceObject = pDeviceObject;
	} else {
		DcDestroy(dc);
		IoDeleteSymbolicLink(&usDosDeviceName);
		IoDeleteDevice(pDeviceObject);
	}

	return rc;
}


_Use_decl_annotations_
VOID
OnDriverUnload(IN PDRIVER_OBJECT pdo)
{
	KdPrint(("Cleaning up YARA Scan Driver\n"));

	//
	// Mark the device as no longer in use so new requests are no longer processed
	// and mark all pending repsonses as having failed
	//
	DEVICE_CONTEXT *dc = GetDeviceContext(pdo->DeviceObject);
	DcLock(dc);
	DcShutdownDevice(dc);
	DcUnlock(dc);

	//
	// Remove hooks (these wait for in-flight calls to finish before returning)
	//
	if (PsSetCreateProcessNotifyRoutineEx(OnCreateProcessEx, TRUE) == STATUS_SUCCESS) {
		KdPrint(("Removed process creation notification routine\n"));
	} else {
		KdPrint(("Unable to remove process creation notification routine\n"));
	}

	if (PsRemoveCreateThreadNotifyRoutine(OnCreateThread) == STATUS_SUCCESS) {
		KdPrint(("Removed thread creation notification routine\n"));
	} else {
		KdPrint(("Unable to remove thread creation notification routine\n"));
	}

	if (PsRemoveLoadImageNotifyRoutine(OnLoadImage) == STATUS_SUCCESS) {
		KdPrint(("Removed image load creation notification routine\n"));
	} else {
		KdPrint(("Unable to remove image load creation notification routine\n"));
	}

	// Complete outstanding IRPs here as per https://msdn.microsoft.com/en-us/library/windows/hardware/ff564892%28v=vs.85%29.aspx
	// Destroy the device context
	DcDestroy(dc);

	// Delete the DosDevices symbolic link
	UNICODE_STRING usDosDeviceName;
	RtlInitUnicodeString(&usDosDeviceName, PROCFILTER_DOSDEVICE_NAME);
	IoDeleteSymbolicLink(&usDosDeviceName);

	// Delete the device object
	if (pdo->DeviceObject) {
		KdPrint(("Deleting device object\n"));
		IoDeleteDevice(pdo->DeviceObject);
	}

	KdPrint(("Exiting YARA Scan Driver\n"));
}
