package psapi

import (
	"syscall"
	"unsafe"
)

const (
	MAX_PATH = 260

	LIST_MODULES_DEFAULT = 0x0
	LIST_MODULES_32BIT   = 0x01
	LIST_MODULES_64BIT   = 0x02
	LIST_MODULES_ALL     = (LIST_MODULES_32BIT | LIST_MODULES_64BIT)
)

type MODULEINFO struct {
	BaseOfDll   unsafe.Pointer
	SizeOfImage uint32
	EntryPoint  unsafe.Pointer
}

var (
	psapiDll = syscall.NewLazyDLL("psapi.dll")

	psEnumProcessModulesEx = psapiDll.NewProc("EnumProcessModulesEx")
	psGetModuleBaseName    = psapiDll.NewProc("GetModuleBaseNameW")
	psGetModuleFileNameEx  = psapiDll.NewProc("GetModuleFileNameExW")
	psGetModuleInformation = psapiDll.NewProc("GetModuleInformation")
)

// BOOL WINAPI EnumProcessModulesEx(
//   _In_  HANDLE  hProcess,
//   _Out_ HMODULE *lphModule,
//   _In_  DWORD   cb,
//   _Out_ LPDWORD lpcbNeeded,
//   _In_  DWORD   dwFilterFlag
// );
// fail == 0
func EnumProcessModulesEx(proc syscall.Handle) ([]syscall.Handle, uint32, error) {
	modules := make([]syscall.Handle, 1024)
	modSize := unsafe.Sizeof(modules[0])
	modulesSize := uintptr(len(modules)) * modSize

	var sizeNeeded uint32

	ret, _, err := psEnumProcessModulesEx.Call(
		uintptr(proc),
		uintptr(unsafe.Pointer(&modules[0])),
		modulesSize,
		uintptr(unsafe.Pointer(&sizeNeeded)),
		uintptr(LIST_MODULES_ALL),
	)

	if ret == 0 {
		return nil, 0, err
	}

	return modules, (sizeNeeded / uint32(modSize)), nil
}

func GetModuleBaseName(proc, module syscall.Handle) (string, error) {
	buffer := make([]uint16, MAX_PATH)

	ret, _, err := psGetModuleBaseName.Call(
		uintptr(proc),
		uintptr(module),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)

	if ret == 0 {
		return "", err
	}

	return syscall.UTF16ToString(buffer), nil
}

// DWORD WINAPI GetModuleFileNameEx(
//   _In_     HANDLE  hProcess,
//   _In_opt_ HMODULE hModule,
//   _Out_    LPTSTR  lpFilename,
//   _In_     DWORD   nSize
// );
// fail == 0
func GetModuleFileNameEx(proc, module syscall.Handle) (string, error) {
	buffer := make([]uint16, MAX_PATH)

	ret, _, err := psGetModuleFileNameEx.Call(
		uintptr(proc),
		uintptr(module),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)

	if ret == 0 {
		return "", err
	}

	return syscall.UTF16ToString(buffer), nil
}

// BOOL WINAPI GetModuleInformation(
//   _In_  HANDLE       hProcess,
//   _In_  HMODULE      hModule,
//   _Out_ LPMODULEINFO lpmodinfo,
//   _In_  DWORD        cb
// );
// fail == 0
func GetModuleInformation(proc, module syscall.Handle) (MODULEINFO, error) {
	var modInfo MODULEINFO

	ret, _, err := psGetModuleInformation.Call(
		uintptr(proc),
		uintptr(module),
		uintptr(unsafe.Pointer(&modInfo)),
		unsafe.Sizeof(modInfo),
	)

	if ret == 0 {
		return modInfo, err
	}

	return modInfo, nil
}
