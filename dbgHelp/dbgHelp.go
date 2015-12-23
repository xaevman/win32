//  ---------------------------------------------------------------------------
//
//  dbgHelp.go
//
//  Copyright (c) 2015, Jared Chavez. 
//  All rights reserved.
//
//  Use of this source code is governed by a BSD-style
//  license that can be found in the LICENSE file.
//
//  -----------

package dbgHelp

import (
    //"fmt"
    "syscall"
    "unsafe"
)

const (
    ERROR_SUCCESS                    = uint32(0)

    SYMSRV_VERSION                   = 2

    SSRVOPT_CALLBACK                 = 0x00000001
    SSRVOPT_DWORD                    = 0x00000002
    SSRVOPT_DWORDPTR                 = 0x00000004
    SSRVOPT_GUIDPTR                  = 0x00000008
    SSRVOPT_OLDGUIDPTR               = 0x00000010
    SSRVOPT_UNATTENDED               = 0x00000020
    SSRVOPT_NOCOPY                   = 0x00000040
    SSRVOPT_GETPATH                  = 0x00000040
    SSRVOPT_PARENTWIN                = 0x00000080
    SSRVOPT_PARAMTYPE                = 0x00000100
    SSRVOPT_SECURE                   = 0x00000200
    SSRVOPT_TRACE                    = 0x00000400
    SSRVOPT_SETCONTEXT               = 0x00000800
    SSRVOPT_PROXY                    = 0x00001000
    SSRVOPT_DOWNSTREAM_STORE         = 0x00002000
    SSRVOPT_OVERWRITE                = 0x00004000
    SSRVOPT_RESETTOU                 = 0x00008000
    SSRVOPT_CALLBACKW                = 0x00010000
    SSRVOPT_FLAT_DEFAULT_STORE       = 0x00020000
    SSRVOPT_PROXYW                   = 0x00040000
    SSRVOPT_MESSAGE                  = 0x00080000
    SSRVOPT_SERVICE                  = 0x00100000   // deprecated
    SSRVOPT_FAVOR_COMPRESSED         = 0x00200000
    SSRVOPT_STRING                   = 0x00400000
    SSRVOPT_WINHTTP                  = 0x00800000
    SSRVOPT_WININET                  = 0x01000000
    SSRVOPT_DONT_UNCOMPRESS          = 0x02000000

    SYMOPT_CASE_INSENSITIVE          = 0x00000001
    SYMOPT_UNDNAME                   = 0x00000002
    SYMOPT_DEFERRED_LOADS            = 0x00000004
    SYMOPT_NO_CPP                    = 0x00000008
    SYMOPT_LOAD_LINES                = 0x00000010
    SYMOPT_OMAP_FIND_NEAREST         = 0x00000020
    SYMOPT_LOAD_ANYTHING             = 0x00000040
    SYMOPT_IGNORE_CVREC              = 0x00000080
    SYMOPT_NO_UNQUALIFIED_LOADS      = 0x00000100
    SYMOPT_FAIL_CRITICAL_ERRORS      = 0x00000200
    SYMOPT_EXACT_SYMBOLS             = 0x00000400
    SYMOPT_ALLOW_ABSOLUTE_SYMBOLS    = 0x00000800
    SYMOPT_IGNORE_NT_SYMPATH         = 0x00001000
    SYMOPT_INCLUDE_32BIT_MODULES     = 0x00002000
    SYMOPT_PUBLICS_ONLY              = 0x00004000
    SYMOPT_NO_PUBLICS                = 0x00008000
    SYMOPT_AUTO_PUBLICS              = 0x00010000
    SYMOPT_NO_IMAGE_SEARCH           = 0x00020000
    SYMOPT_SECURE                    = 0x00040000
    SYMOPT_NO_PROMPTS                = 0x00080000
    SYMOPT_OVERWRITE                 = 0x00100000
    SYMOPT_IGNORE_IMAGEDIR           = 0x00200000
    SYMOPT_FLAT_DIRECTORY            = 0x00400000
    SYMOPT_FAVOR_COMPRESSED          = 0x00800000
    SYMOPT_ALLOW_ZERO_ADDRESS        = 0x01000000
    SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000
    SYMOPT_READONLY_CACHE            = 0x04000000
    SYMOPT_SYMPATH_LAST              = 0x08000000
    SYMOPT_DEBUG                     = 0x80000000
)

type DWORD   uint32
type DWORD64 uint64

var (
    // dll imports
    dbgHelpDll  = syscall.NewLazyDLL("dbgHelp.dll")

    // dbgHelp functions
    symSrvGetfileIndexInfo = dbgHelpDll.NewProc("SymSrvGetFileIndexInfo")
    symSetOptions          = dbgHelpDll.NewProc("SymSetOptions")
    symInitialize          = dbgHelpDll.NewProc("SymInitialize")
    symFindFileInPath      = dbgHelpDll.NewProc("SymFindFileInPathW")
    symLoadModuleEx        = dbgHelpDll.NewProc("SymLoadModuleEx")
    symFromAddr            = dbgHelpDll.NewProc("SymFromAddr")
    symGetLineFromAddr64   = dbgHelpDll.NewProc("SymGetLineFromAddr64")
    symCleanup             = dbgHelpDll.NewProc("SymCleanup")
)

func SymCleanup (proc syscall.Handle) error {
    ret, _, err := symCleanup.Call(uintptr(proc))
    if uint32(ret) == 0 {
        return err
    }

    return nil
}

func SymSetOptions (optFlags uint32) uint32 {
    ret, _, _ := symSetOptions.Call(
        uintptr(optFlags),
    )

    return uint32(ret)
}

func SymInitialize (proc syscall.Handle, searchPath string, invadeProcess bool) error {
    ret, _, err := symInitialize.Call(
        uintptr(proc),
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(searchPath))),
        0,
    )

    if uint32(ret) == 0 {
        return err
    }

    return nil
}
