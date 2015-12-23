//  ---------------------------------------------------------------------------
//
//  all_test.go
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
    "fmt"
    "syscall"
    "testing"
)

func TestSymlookup (t *testing.T) {
    fmt.Println("Modules Loaded")

    proc := syscall.GetCurrentProcess()
    opts := SymSetOptions(
        SYMOPT_EXACT_SYMBOLS | 
        SYMOPT_LOAD_LINES | 
        SYMOPT_FAIL_CRITICAL_ERRORS | 
        SYMOPT_UNDNAME,
    )

    fmt.Printf("Currenet options mask 0x%x\n", opts)

    err := SymInitialize(proc, "C:\\ul\\SymSrv\\test", false)
    if err != nil {
        panic(err)
    }

    fmt.Println("Initialized")

    err = SymCleanup(proc)
    if err != nil {
        panic(err)
    }

    fmt.Println("Cleanup complete")
}
