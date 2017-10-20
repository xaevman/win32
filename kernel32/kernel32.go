package kernel32

import (
	"fmt"
	"syscall"
	"unsafe"
)

// typedef enum {
//     AddrMode1616,
//     AddrMode1632,
//     AddrModeReal,
//     AddrModeFlat
// } ADDRESS_MODE;
const (
	AddrMode1616 = iota
	AddrMode1632
	AddrModeReal
	AddrModeFlat
)

const (
	MAX_PATH = 260

	INVALID_HANDLE_VALUE = -1

	DELETE       = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC    = 0x00040000
	WRITE_OWNER  = 0x00080000
	SYNCHRONIZE  = 0x00100000

	CONTEXT_AMD64           = 0x00100000
	CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x00000001)
	CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x00000002)
	CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x00000004)
	CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x00000008)
	CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x00000010)
	CONTEXT_FULL            = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
	CONTEXT_ALL             = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)
	CONTEXT_XSTATE          = (CONTEXT_AMD64 | 0x00000040)

	EVENT_MODIFY_STATE = 0x0002
	EVENT_ALL_ACCESS   = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3)

	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_ALL      = 0x001F0000

	SPECIFIC_RIGHTS_ALL = 0x0000FFFF

	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_SET_SESSIONID             = 0x0004
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_LIMITED_INFORMATION   = 0x2000
	PROCESS_ALL_ACCESS                = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

	TH32CS_SNAPHEAPLIST = 0x00000001
	TH32CS_SNAPPROCESS  = 0x00000002
	TH32CS_SNAPTHREAD   = 0x00000004
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010
	TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
	TH32CS_INHERIT      = 0x80000000

	THREAD_TERMINATE                 = 0x0001
	THREAD_SUSPEND_RESUME            = 0x0002
	THREAD_GET_CONTEXT               = 0x0008
	THREAD_SET_CONTEXT               = 0x0010
	THREAD_QUERY_INFORMATION         = 0x0040
	THREAD_SET_INFORMATION           = 0x0020
	THREAD_SET_THREAD_TOKEN          = 0x0080
	THREAD_IMPERSONATE               = 0x0100
	THREAD_DIRECT_IMPERSONATION      = 0x0200
	THREAD_SET_LIMITED_INFORMATION   = 0x0400
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800
	THREAD_RESUME                    = 0x1000
	THREAD_ALL_ACCESS                = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

	JOB_OBJECT_ASSIGN_PROCESS          = 0x0001
	JOB_OBJECT_SET_ATTRIBUTES          = 0x0002
	JOB_OBJECT_QUERY                   = 0x0004
	JOB_OBJECT_TERMINATE               = 0x0008
	JOB_OBJECT_SET_SECURITY_ATTRIBUTES = 0x0010
	JOB_OBJECT_IMPERSONATE             = 0x0020
	JOB_OBJECT_ALL_ACCESS              = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3F)
)

type M128A struct {
	Low  uint64
	High int64
}

type CONTEXT struct {
	//
	// Register parameter home addresses.
	//
	// N.B. These fields are for convience - they could be used to extend the
	//      context record in the future.
	//
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	//
	// Control flags.
	//
	ContextFlags uint32
	MxCsr        uint32

	//
	// Segment Registers and processor flags.
	//
	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	//
	// Debug registers
	//
	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	//
	// Integer registers.
	//
	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64

	//
	// Program counter.
	//
	Rip uint64

	//
	// Floating point state.
	//
	FltSave [512]byte

	//
	// Vector registers.
	//
	VectorRegister [26]M128A
	VectorControl  uint64

	//
	// Special debug control registers.
	//
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

var (
	// dll imports
	kernel32Dll = syscall.NewLazyDLL("kernel32.dll")

	// functions
	k32CloseHandle              = kernel32Dll.NewProc("CloseHandle")
	k32CreateEvent              = kernel32Dll.NewProc("CreateEventExW")
	k32CreateToolhelp32Snapshot = kernel32Dll.NewProc("CreateToolhelp32Snapshot")
	k32GetThreadContext         = kernel32Dll.NewProc("GetThreadContext")
	k32LocalFree                = kernel32Dll.NewProc("LocalFree")
	k32OpenEvent                = kernel32Dll.NewProc("OpenEventW")
	k32OpenProcess              = kernel32Dll.NewProc("OpenProcess")
	k32OpenThread               = kernel32Dll.NewProc("OpenThread")
	k32ResumeThread             = kernel32Dll.NewProc("ResumeThread")
	k32SuspendThread            = kernel32Dll.NewProc("SuspendThread")
	k32Thread32First            = kernel32Dll.NewProc("Thread32First")
	k32Thread32Next             = kernel32Dll.NewProc("Thread32Next")
	k32ReadProcessMemory        = kernel32Dll.NewProc("ReadProcessMemory")
	k32SetEvent                 = kernel32Dll.NewProc("SetEvent")
	k32WriteProcessMemory       = kernel32Dll.NewProc("WriteProcessMemory")
	k32WaitOnAddress            = kernel32Dll.NewProc("WaitOnAddress")
)

// BOOL  WINAPI WaitOnAddress(
//   _In_     VOID   volatile *Address,
//   _In_     PVOID           CompareAddress,
//   _In_     SIZE_T          AddressSize,
//   _In_opt_ DWORD           dwMilliseconds
// );
// fail == 0
func WaitOnAddress(watch, compare *byte, timeout uint32) error {
	ret, _, err := k32WaitOnAddress.Call(
		uintptr(unsafe.Pointer(watch)),
		uintptr(unsafe.Pointer(compare)),
		unsafe.Sizeof(watch),
		uintptr(timeout),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// BOOL WINAPI WriteProcessMemory(
//   _In_  HANDLE  hProcess,
//   _In_  LPVOID  lpBaseAddress,
//   _In_  LPCVOID lpBuffer,
//   _In_  SIZE_T  nSize,
//   _Out_ SIZE_T  *lpNumberOfBytesWritten
// );
// fail == 0
func WriteProcessMemory(proc syscall.Handle, addr, size, buffer uintptr) error {
	var written uint32
	ret, _, err := k32WriteProcessMemory.Call(
		uintptr(proc),
		addr,
		buffer,
		size,
		uintptr(unsafe.Pointer(&written)),
	)

	if ret == 0 {
		return err
	}

	if uintptr(written) != size {
		return fmt.Errorf("Written size mismatch (%d != %d)", written, size)
	}

	return nil
}

// HANDLE WINAPI CreateEventEx(
//   _In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
//   _In_opt_ LPCTSTR               lpName,
//   _In_     DWORD                 dwFlags,
//   _In_     DWORD                 dwDesiredAccess
// );
// fail == 0
func CreateEvent(name string) (uintptr, error) {
	ret, _, err := k32CreateEvent.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		0,
		EVENT_ALL_ACCESS,
	)

	if ret == 0 {
		return 0, err
	}

	return ret, nil
}

// HANDLE WINAPI OpenEvent(
//   _In_ DWORD   dwDesiredAccess,
//   _In_ BOOL    bInheritHandle,
//   _In_ LPCTSTR lpName
// );
// fail == 0
func OpenEvent(inheritHandle bool, name string) (uintptr, error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	ret, _, err := k32OpenEvent.Call(
		uintptr(EVENT_MODIFY_STATE),
		uintptr(inherit),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
	)

	if ret == 0 {
		return 0, err
	}

	return ret, nil
}

// BOOL WINAPI SetEvent(
//   _In_ HANDLE hEvent
// );
// fail == 0
func SetEvent(event uintptr) error {
	ret, _, err := k32SetEvent.Call(event)
	if ret == 0 {
		return err
	}

	return nil
}

// BOOL WINAPI ReadProcessMemory(
//   _In_  HANDLE  hProcess,
//   _In_  LPCVOID lpBaseAddress,
//   _Out_ LPVOID  lpBuffer,
//   _In_  SIZE_T  nSize,
//   _Out_ SIZE_T  *lpNumberOfBytesRead
// );
// fail == 0
func ReadProcessMemory(proc syscall.Handle, addr uint64, size uint64) ([]byte, error) {
	buffer := make([]byte, size)
	var bytesRead uint64

	ret, _, err := k32ReadProcessMemory.Call(
		uintptr(proc),
		uintptr(addr),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return nil, err
	}

	return buffer, nil
}

// HANDLE WINAPI CreateToolhelp32Snapshot(
//   _In_ DWORD dwFlags,
//   _In_ DWORD th32ProcessID
// );
// fail == INVALID_HANDLE_VALUE
func CreateThreadSnapshot(pid uint32) (int64, error) {
	ret, _, err := k32CreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPTHREAD),
		uintptr(pid),
	)
	if int64(ret) == INVALID_HANDLE_VALUE {
		return 0, err
	}

	return int64(ret), nil
}

// BOOL WINAPI GetThreadContext(
//   _In_    HANDLE    hThread,
//   _Inout_ LPCONTEXT lpContext
// );
// fail == 0
func GetThreadContext(threadHandle uintptr) (*CONTEXT, error) {
	var context CONTEXT
	context.ContextFlags = CONTEXT_FULL

	ret, _, err := k32GetThreadContext.Call(
		threadHandle,
		uintptr(unsafe.Pointer(&context)),
	)

	if ret == 0 {
		return nil, err
	}

	return &context, nil
}

func LocalFree(p unsafe.Pointer) error {
	ret, _, err := k32LocalFree.Call(uintptr(p))
	if ret != 0 {
		return err
	}

	return nil
}

func OpenProcess(pid uint32) (syscall.Handle, error) {
	ret, _, err := k32OpenProcess.Call(
		uintptr(PROCESS_ALL_ACCESS),
		0,
		uintptr(pid),
	)

	if uint32(ret) == 0 {
		return syscall.InvalidHandle, err
	}

	return syscall.Handle(ret), nil
}

// HANDLE WINAPI OpenThread(
//   _In_ DWORD dwDesiredAccess,
//   _In_ BOOL  bInheritHandle,
//   _In_ DWORD dwThreadId
// );
// fail == 0
func OpenThread(threadId uint32) (uintptr, error) {
	ret, _, err := k32OpenThread.Call(
		THREAD_ALL_ACCESS,
		uintptr(0),
		uintptr(threadId),
	)

	if ret == 0 {
		return 0, err
	}

	return ret, nil
}

// DWORD WINAPI ResumeThread(
//   _In_ HANDLE hThread
// );
// fail == -1
func ResumeThread(threadHandle uintptr) error {
	ret, _, err := k32ResumeThread.Call(threadHandle)

	if int32(ret) == -1 {
		return err
	}

	return nil
}

// DWORD WINAPI SuspendThread(
//   _In_ HANDLE hThread
// );
// fail == -1
func SuspendThread(threadHandle uintptr) error {
	ret, _, err := k32SuspendThread.Call(threadHandle)

	if (int32(ret)) == -1 {
		return err
	}

	return nil
}

// BOOL WINAPI Thread32First(
//   _In_    HANDLE          hSnapshot,
//   _Inout_ LPTHREADENTRY32 lpte
// );
// fail == false
func Thread32First(snapshot int64, threadEntry *THREADENTRY32) error {
	threadEntry.Size = uint32(unsafe.Sizeof(*threadEntry))

	ret, _, err := k32Thread32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(threadEntry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

// BOOL WINAPI Thread32Next(
//   _In_  HANDLE          hSnapshot,
//   _Out_ LPTHREADENTRY32 lpte
// );
// fail = false
func Thread32Next(snapshot int64, threadEntry *THREADENTRY32) error {
	threadEntry.Size = uint32(unsafe.Sizeof(*threadEntry))

	ret, _, err := k32Thread32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(threadEntry)),
	)

	if ret == 0 {
		return err
	}

	return nil
}
