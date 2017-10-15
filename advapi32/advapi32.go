package advapi32

import (
	"syscall"
	"unsafe"

	"github.com/xaevman/win32/kernel32"
)

const (
	SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
	DOMAIN_ALIAS_RID_ADMINS     = 0x00000220
)

var (
	NT_AUTHORITY = [6]uint8{0, 0, 0, 0, 0, 5}
)

var (
	// dll imports
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	// functions
	advAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	advCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
	advConvertSidToStringSid    = advapi32.NewProc("ConvertSidToStringSidW")
	advFreeSid                  = advapi32.NewProc("FreeSid")
)

type SID struct{}

func AllocateAndInitializeSid(authority [6]uint8) (*SID, error) {
	var sid *SID

	ret, _, err := advAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&authority[0])),
		uintptr(2),
		uintptr(SECURITY_BUILTIN_DOMAIN_RID),
		uintptr(DOMAIN_ALIAS_RID_ADMINS),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&sid)),
	)

	if uint32(ret) == 0 {
		return nil, err
	}

	return sid, nil
}

func FreeSid(sid *SID) error {
	ret, _, err := advFreeSid.Call(uintptr(unsafe.Pointer(sid)))
	if ret == 0 {
		return err
	}

	return nil
}

func PrintSid(sid *SID) (string, error) {
	var sidStr *uint16

	ret, _, err := advConvertSidToStringSid.Call(
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&sidStr)),
	)

	if uint32(ret) == 0 {
		return "", err
	}

	defer kernel32.LocalFree(unsafe.Pointer(sidStr))

	return syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(sidStr))[:]), nil
}

func CheckTokenMembership(token uintptr, sid *SID) (bool, error) {
	var result int32

	ret, _, err := advCheckTokenMembership.Call(
		token,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&result)),
	)

	if uint32(ret) == 0 {
		return false, err
	}

	return result != 0, nil
}
