package shell32

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	SEE_MASK_DEFAULT            = 0x00000000
	SEE_MASK_CLASSNAME          = 0x00000001       // SHELLEXECUTEINFO.lpClass is valid
	SEE_MASK_CLASSKEY           = 0x00000003       // SHELLEXECUTEINFO.hkeyClass is valid
	SEE_MASK_IDLIST             = 0x00000004       // SHELLEXECUTEINFO.lpIDList is valid
	SEE_MASK_INVOKEIDLIST       = 0x0000000c       // enable IContextMenu based verbs
	SEE_MASK_ICON               = 0x00000010       // not used
	SEE_MASK_HOTKEY             = 0x00000020       // SHELLEXECUTEINFO.dwHotKey is valid
	SEE_MASK_NOCLOSEPROCESS     = 0x00000040       // SHELLEXECUTEINFO.hProcess
	SEE_MASK_CONNECTNETDRV      = 0x00000080       // enables re-connecting disconnected network drives
	SEE_MASK_NOASYNC            = 0x00000100       // block on the call until the invoke has completed, use for callers that exit after calling ShellExecuteEx()
	SEE_MASK_FLAG_DDEWAIT       = SEE_MASK_NOASYNC // Use SEE_MASK_NOASYNC instead of SEE_MASK_FLAG_DDEWAIT as it more accuratly describes the behavior
	SEE_MASK_DOENVSUBST         = 0x00000200       // indicates that SHELLEXECUTEINFO.lpFile contains env vars that should be expanded
	SEE_MASK_FLAG_NO_UI         = 0x00000400       // disable UI including error messages
	SEE_MASK_UNICODE            = 0x00004000
	SEE_MASK_NO_CONSOLE         = 0x00008000
	SEE_MASK_ASYNCOK            = 0x00100000
	SEE_MASK_HMONITOR           = 0x00200000 // SHELLEXECUTEINFO.hMonitor
	SEE_MASK_NOZONECHECKS       = 0x00800000
	SEE_MASK_NOQUERYCLASSSTORE  = 0x01000000
	SEE_MASK_WAITFORINPUTIDLE   = 0x02000000
	SEE_MASK_FLAG_LOG_USAGE     = 0x04000000
	SEE_MASK_FLAG_HINST_IS_SITE = 0x08000000

	SW_HIDE            = 0
	SW_SHOWNORMAL      = 1
	SW_NORMAL          = 1
	SW_SHOWMINIMIZED   = 2
	SW_SHOWMAXIMIZED   = 3
	SW_MAXIMIZE        = 3
	SW_SHOWNOACTIVATE  = 4
	SW_SHOW            = 5
	SW_MINIMIZE        = 6
	SW_SHOWMINNOACTIVE = 7
	SW_SHOWNA          = 8
	SW_RESTORE         = 9
	SW_SHOWDEFAULT     = 10
	SW_FORCEMINIMIZE   = 11
	SW_MAX             = 11
)

type SHELLEXECUTEINFOW struct {
	Size       uint32         // in, required, sizeof of this structure
	Mask       uint32         // in, SEE_MASK_XXX values
	HWND       syscall.Handle // in, optional
	Verb       *uint16        // in, optional when unspecified the default verb is choosen
	File       *uint16        // in, either this value or lpIDList must be specified
	Parameters *uint16        // in, optional
	Directory  *uint16        // in, optional
	Show       int            // in, required
	InstApp    syscall.Handle // out when SEE_MASK_NOCLOSEPROCESS is specified
	IDList     unsafe.Pointer // in, valid when SEE_MASK_IDLIST is specified, PCIDLIST_ABSOLUTE, for use with SEE_MASK_IDLIST & SEE_MASK_INVOKEIDLIST
	Class      *uint16        // in, valid when SEE_MASK_CLASSNAME is specified
	KeyClass   syscall.Handle // in, valid when SEE_MASK_CLASSKEY is specified
	HotKey     uint32         // in, valid when SEE_MASK_HOTKEY is specified
	Icon       syscall.Handle // not used
	Process    syscall.Handle // out, valid when SEE_MASK_NOCLOSEPROCESS specified
}

var (
	shell32Dll = syscall.NewLazyDLL("Shell32.dll")

	shShellExecuteEx = shell32Dll.NewProc("ShellExecuteExW")
)

func ExecuteElevated(cmd string, args []string) error {
	cmdPtr, err := syscall.UTF16PtrFromString(cmd)
	if err != nil {
		return fmt.Errorf("Error converting cmd (%s) : %v", cmd, err)
	}

	argsStr := strings.Join(args, " ")
	argsPtr, err := syscall.UTF16PtrFromString(argsStr)
	if err != nil {
		return fmt.Errorf("Error converting args (%s) : %v", args, err)
	}

	verbPtr, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("Error converting verb (runas) : %v", err)
	}

	var execInfo SHELLEXECUTEINFOW
	execInfo.Size = uint32(unsafe.Sizeof(execInfo))
	execInfo.Mask = SEE_MASK_UNICODE | SEE_MASK_NOCLOSEPROCESS
	execInfo.File = cmdPtr
	execInfo.Verb = verbPtr
	execInfo.Show = SW_SHOW
	execInfo.Parameters = argsPtr

	ret, _, err := shShellExecuteEx.Call(
		uintptr(unsafe.Pointer(&execInfo)),
	)

	if ret == 0 {
		return fmt.Errorf("Error calling ShellExecuteEx: %v", err)
	}
	defer syscall.CloseHandle(execInfo.Process)

	syscall.WaitForSingleObject(execInfo.Process, syscall.INFINITE)

	var exitCode uint32
	err = syscall.GetExitCodeProcess(execInfo.Process, &exitCode)
	if err != nil {
		return fmt.Errorf("Error getting process exit code: %v", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("Process exited with code %d", exitCode)
	}

	return nil
}
