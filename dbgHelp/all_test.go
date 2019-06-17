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

package dbg

import (
    "fmt"
    "syscall"
    "testing"
)

func TestSymInitAndClose(t *testing.T) {
    fmt.Println("Modules Loaded")

    proc, err := syscall.GetCurrentProcess()
    if err != nil {
        t.Fail()
    }

    opts := SymSetOptions(
        SYMOPT_EXACT_SYMBOLS |
            SYMOPT_LOAD_LINES |
            SYMOPT_FAIL_CRITICAL_ERRORS |
            SYMOPT_UNDNAME,
    )

    fmt.Printf("Currenet options mask 0x%x\n", opts)

    err = SymInitialize(proc, "", false)
    if err != nil {
        t.Fatal(err)
    }

    fmt.Println("Initialized")

    err = SymCleanup(proc)
    if err != nil {
        t.Fatal(err)
    }

    fmt.Println("Cleanup complete")
}
