//  ---------------------------------------------------------------------------
//
//  pdh.go
//
//  Copyright (c) 2015, Jared Chavez. 
//  All rights reserved.
//
//  Use of this source code is governed by a BSD-style
//  license that can be found in the LICENSE file.
//
//  -----------

package pdh

import (
    "fmt"
    "syscall"
    "unsafe"
)

// PDH error codes and constants
const (
    ERROR_SUCCESS  = uint32(0)
    PDH_FMT_DOUBLE = 0x0200
    PDH_MORE_DATA  = 0x800007D2
)

// PDH dll imports
var (
    pdhDll = syscall.NewLazyDLL("pdh.dll")

    pdhAddCounter               = pdhDll.NewProc("PdhAddCounterW")
    pdhCloseQuery               = pdhDll.NewProc("PdhCloseQuery")
    pdhCollectQueryData         = pdhDll.NewProc("PdhCollectQueryData")
    pdhExpandCounterPath        = pdhDll.NewProc("PdhExpandCounterPathW")
    pdhGetDllVersion            = pdhDll.NewProc("PdhGetDllVersion")
    pdhGetFormattedCounterValue = pdhDll.NewProc("PdhGetFormattedCounterValue")
    pdhOpenQuery                = pdhDll.NewProc("PdhOpenQueryW")
    pdhRemoveCounter            = pdhDll.NewProc("PdhRemoveCounter")
)

// PDH formatted (DOUBLE) counter value
type PdhDblCounterVal struct {
    CStatus uint32
    Value   float64
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372204(v=vs.85).aspx
func PdhAddCounter(
    query       *syscall.Handle, 
    counterName string,
) (*syscall.Handle, error) {
    var counter syscall.Handle

    ret, _, _ := pdhAddCounter.Call(
        uintptr(*query),
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(counterName))),
        0,
        uintptr(unsafe.Pointer(&counter)),
    )

    return &counter, getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372558(v=vs.85).aspx
func PdhCloseQuery(query *syscall.Handle) error {
    ret, _, _ := pdhCloseQuery.Call(uintptr(*query))
    return getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372563(v=vs.85).aspx
func PdhCollectQueryData(query *syscall.Handle) error {
    ret, _, _ := pdhCollectQueryData.Call(uintptr(*query))
    return getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372605(v=vs.85).aspx
func PdhExpandCounterPath(path string) ([]string, error) {
    var buffSize uint32

    // get number of paths
    ret, _, _ := pdhExpandCounterPath.Call(
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(path))),
        0,
        uintptr(unsafe.Pointer(&buffSize)),
    )

    if uint32(ret) != PDH_MORE_DATA {
        panic(ret)
    }

    buffer := make([]uint16, buffSize)
    ret, _, _ = pdhExpandCounterPath.Call(
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(path))),
        uintptr(unsafe.Pointer(&buffer[0])),
        uintptr(unsafe.Pointer(&buffSize)),
    )

    if uint32(ret) != ERROR_SUCCESS {
        return nil, getError(ret)
    }

    paths := make([]string, 0)
    head  := 0
    for tail := 0; tail < len(buffer); tail++ {
        if buffer[tail] == 0 {
            paths = append(paths, syscall.UTF16ToString(buffer[head:tail]))
            head = tail + 1
            tail++
        }
    }

    return paths, getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372630(v=vs.85).aspx
func PdhGetDllVersion() (uint32, error) {
    var ver uint32
    ret, _, _ := pdhGetDllVersion.Call(uintptr(unsafe.Pointer(&ver)))

    return ver, getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372637(v=vs.85).aspx
func PdhGetFormattedCounterValue(counter *syscall.Handle) (*PdhDblCounterVal, error) {
    var val PdhDblCounterVal

    ret, _, _ := pdhGetFormattedCounterValue.Call(
        uintptr(*counter),
        PDH_FMT_DOUBLE,
        0,
        uintptr(unsafe.Pointer(&val)),
    )

    return &val, getError(ret)
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372652(v=vs.85).aspx
func PdhOpenQuery() (*syscall.Handle, error) {
    var query syscall.Handle
    ret, _, _ := pdhOpenQuery.Call(
        0,
        0,
        uintptr(unsafe.Pointer(&query)),
    )

    return &query, getError(ret)
}
 
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa372665(v=vs.85).aspx
func PdhRemoveCounter(counter *syscall.Handle) error {
    ret, _, _ := pdhRemoveCounter.Call(uintptr(*counter))
    return getError(ret)
}

// getError converts PDH errors into golang error objects, unless the returnVal equals
// ERROR_SUCCESS, then it just returns null.
func getError(returnVal uintptr) error {
    ret := uint32(returnVal)
    if ret == ERROR_SUCCESS {
        return nil
    }

    return fmt.Errorf("%d", ret)
}
