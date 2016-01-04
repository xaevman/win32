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

package dbg

import (
    "fmt"
    "strconv"
    "strings"
    "syscall"
    "unsafe"
)

const (
    ERROR_SUCCESS                    = uint32(0)

    MAX_PATH                         = 260
    MAX_SYM_NAME                     = 2000

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

type SYMSRV_INDEX_INFOW struct {
    Sizeofstruct uint32
    File         [MAX_PATH + 1]uint16
    Stripped     uint32
    Timestamp    uint32
    Size         uint32
    Dbgfile      [MAX_PATH + 1]uint16
    Pdbfile      [MAX_PATH + 1]uint16
    Guid         GUID
    Sig          uint32
    Age          uint32
}

type SYMBOL_INFOW struct {
    SizeOfStruct uint32
    TypeIndex    uint32
    Reserved     [2]uint64
    Index        uint32
    Size         uint32
    ModBase      uint64
    Flags        uint32
    Value        uint64
    Address      uint64
    Register     uint32
    Scope        uint32
    Tag          uint32
    NameLen      uint32
    MaxNameLen   uint32
    Name         [MAX_SYM_NAME]uint16
}

type IMAGEHLP_LINEW64 struct {
    SizeOfStruct uint32
    Key          uintptr
    LineNumber   uint32
    FileName     uintptr
    Address      uint64
}

type GUID struct {
    Data1 uint32
    Data2 uint16
    Data3 uint16
    Data4 [8]uint8
} 

type PdbInfo struct {
    Age        uint32
    Guid       GUID
    SymSrvInfo SYMSRV_INDEX_INFOW
}

type SymbolInfo struct {
    Address    uint64
    Name       string
    FileName   string
    LineNumber uint32
}

var (
    // dll imports
    dbgHelpDll  = syscall.NewLazyDLL("dbgHelp.dll")

    // dbgHelp functions
    symSrvGetFileIndexInfo = dbgHelpDll.NewProc("SymSrvGetFileIndexInfoW")
    symSetOptions          = dbgHelpDll.NewProc("SymSetOptions")
    symInitialize          = dbgHelpDll.NewProc("SymInitializeW")
    symFindFileInPath      = dbgHelpDll.NewProc("SymFindFileInPathW")
    symLoadModuleEx        = dbgHelpDll.NewProc("SymLoadModuleExW")
    symFromAddr            = dbgHelpDll.NewProc("SymFromAddrW")
    symGetLineFromAddr64   = dbgHelpDll.NewProc("SymGetLineFromAddrW64")
    symCleanup             = dbgHelpDll.NewProc("SymCleanup")
)

func ResolveSymbol(proc syscall.Handle, symAddr uint64) (*SymbolInfo, error) {
    symData, err := SymFromAddr(proc, symAddr)
    if err != nil {
        return nil, err
    }

    lineInfo, err := SymGetLineFromAddr64(proc, symAddr)
    if err != nil {
        return nil, err
    }

    symInfo := &SymbolInfo{
        Address    : symData.Address,
        Name       : syscall.UTF16ToString(symData.Name[:]),
        FileName   : UTF16PtrToString(lineInfo.FileName),
        LineNumber : lineInfo.LineNumber,
    }

    return symInfo, nil
}

func StringToGuid(data string) (GUID, error) {
    guid := GUID{}

    guidParts := strings.Split(data, "-")
    if len(guidParts) != 5 {
        return guid, fmt.Errorf(
            "Invalid number of GUID sections (%d)", 
            len(guidParts),
        )
    }

    // Data1
    p1, err := strconv.ParseUint(guidParts[0], 16, 32)
    if err != nil {
        return guid, err
    }
    guid.Data1 = uint32(p1)

    // Data2
    p2, err := strconv.ParseUint(guidParts[1], 16, 16)
    if err != nil {
        return guid, err
    }
    guid.Data2 = uint16(p2)

    // Data3
    p3, err := strconv.ParseUint(guidParts[2], 16, 16)
    if err != nil {
        return guid, err
    }
    guid.Data3 = uint16(p3)

    // Data4
    for i := 0; i < 2; i++ {
        tmp, err := strconv.ParseUint(guidParts[3][i * 2:(i * 2) + 2], 16, 8)
        if err != nil {
            return guid, err
        }

        guid.Data4[i] = uint8(tmp)
    }

    for i := 0; i < 6; i++ {
        tmp, err := strconv.ParseUint(guidParts[4][i * 2:(i * 2) + 2], 16, 8)
        if err != nil {
            return guid, err
        }
        
        guid.Data4[i + 2] = uint8(tmp)
    }

    return guid, nil
}

func SymCleanup(proc syscall.Handle) error {
    ret, _, err := symCleanup.Call(uintptr(proc))
    if uint32(ret) == 0 {
        fmt.Println(err)
        return err
    }

    return nil
}

func SymFindFileInPath(
    proc     syscall.Handle, 
    fileName string, 
    guid     GUID, 
    age      uint32,
) (string, error) {
    buffer := make([]uint16, MAX_PATH)

    idxInfo             := SYMSRV_INDEX_INFOW{}
    idxInfo.Sizeofstruct = uint32(unsafe.Sizeof(idxInfo))

    pdbInfo           := new(PdbInfo)
    pdbInfo.Age        = age
    pdbInfo.Guid       = guid
    pdbInfo.SymSrvInfo = idxInfo

    ret, _, err := symFindFileInPath.Call(
        uintptr(proc),
        uintptr(0),
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fileName))),
        0,
        0,
        0,
        uintptr(SSRVOPT_GUIDPTR),
        uintptr(unsafe.Pointer(&buffer[0])),
        syscall.NewCallback(onFindFile),
        uintptr(unsafe.Pointer(pdbInfo)),
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return "", err
    }

    return syscall.UTF16ToString(buffer), nil
}

func SymFromAddr(proc syscall.Handle, symAddr uint64) (*SYMBOL_INFOW, error) {
    symInfo             := SYMBOL_INFOW{}
    symInfo.SizeOfStruct = uint32(unsafe.Sizeof(symInfo)) - uint32(MAX_SYM_NAME * 2)
    symInfo.MaxNameLen   = MAX_SYM_NAME

    tmp := uint64(0)

    ret, _, err := symFromAddr.Call(
        uintptr(proc),
        uintptr(symAddr),
        uintptr(unsafe.Pointer(&tmp)),
        uintptr(unsafe.Pointer(&symInfo)),
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return nil, err
    }

    return &symInfo, nil
}

func SymGetLineFromAddr64(
    proc    syscall.Handle, 
    symAddr uint64,
) (*IMAGEHLP_LINEW64, error) {
    tmp := uint32(0)

    lineInfo             := IMAGEHLP_LINEW64{}
    lineInfo.SizeOfStruct = uint32(unsafe.Sizeof(lineInfo))

    ret, _, err := symGetLineFromAddr64.Call(
        uintptr(proc),
        uintptr(symAddr),
        uintptr(unsafe.Pointer(&tmp)),
        uintptr(unsafe.Pointer(&lineInfo)),
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return nil, err
    }

    return &lineInfo, nil
}

func SymInitialize(
    proc          syscall.Handle, 
    searchPath    string, 
    invadeProcess bool,
) error {
    ret, _, err := symInitialize.Call(
        uintptr(proc),
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(searchPath))),
        0,
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return err
    }

    return nil
}

func SymLoadModuleEx(
    proc     syscall.Handle,
    imgName  string,
    baseAddr uint64,
    size     uint32,
) (uint64, error) {
    ret, _, err := symLoadModuleEx.Call(
        uintptr(proc),
        0,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(imgName))),
        0,
        uintptr(baseAddr),
        uintptr(size),
        0,
        0,
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return 0, err
    }

    return uint64(ret), nil
}

func SymSetOptions(optFlags uint32) uint32 {
    ret, _, _ := symSetOptions.Call(uintptr(optFlags))
    return uint32(ret)
}

func SymSrvGetFileIndexInfo(fileName string, idxInfo *SYMSRV_INDEX_INFOW) error {
    ret, _, err := symSrvGetFileIndexInfo.Call(
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(fileName))),
        uintptr(unsafe.Pointer(idxInfo)),
        0,
    )

    if uint32(ret) == 0 {
        fmt.Println(err)
        return err
    }

    return nil
}

func UTF16PtrToString(s uintptr) string {
    if s == 0 {
        return ""
    }
    return syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(s))[0:])
}

func onFindFile(fileNamePtr, context uintptr) uintptr {
    fileName := UTF16PtrToString(fileNamePtr)
    fmt.Printf("Found symbol: %s\n", fileName)

    pdbInfo := (*PdbInfo)(unsafe.Pointer(context))

    err := SymSrvGetFileIndexInfo(fileName, &pdbInfo.SymSrvInfo)
    if err != nil {
        fmt.Println(err)
        return uintptr(1)
    }

    if pdbInfo.SymSrvInfo.Age != pdbInfo.Age {
        fmt.Printf(
            "Age mismatch :: %d != %d\n",
            pdbInfo.SymSrvInfo.Age,
            pdbInfo.Age,
        )
        return uintptr(1)
    }

    if pdbInfo.SymSrvInfo.Guid != pdbInfo.Guid {
        fmt.Printf(
            "Guid mismatch :: %v != %v\n",
            pdbInfo.SymSrvInfo.Guid,
            pdbInfo.Guid,
        )
        return uintptr(1)
    }

    fmt.Printf("Matched at path: %s\n", fileName)

    return uintptr(0)
}
