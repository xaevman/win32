//  ---------------------------------------------------------------------------
//
//  svc.go
//
//  Copyright (c) 2016, Jared Chavez.
//  All rights reserved.
//
//  Use of this source code is governed by a BSD-style
//  license that can be found in the LICENSE file.
//
//  -----------

package svc

import (
    "syscall"
    "unsafe"
)

// SC_ACTION_TYPE enum
const (
    SC_ACTION_NONE = iota
    SC_ACTION_RESTART
    SC_ACTION_REBOOT
    SC_ACTION_RUN_COMMAND
)

const (
    SERVICE_CONFIG_FAILURE_ACTIONS = 2
)

type SERVICE_FAILURE_ACTIONS struct {
    ResetPeriod  uint32
    RebootMsg    uintptr
    Command      uintptr
    ActionsCount uint32
    Actions      uintptr
}

type SC_ACTION struct {
    Type  uint32
    Delay uint32
}

var (
    // dll imports
    advapi32 = syscall.NewLazyDLL("Advapi32.dll")

    // dbgHelp functions
    svcChangeServiceConfig2 = advapi32.NewProc("ChangeServiceConfig2W")
)

func SetFailureFlags(handle syscall.Handle) error {
    var actions [3]SC_ACTION

    actions[0] = SC_ACTION{
        Type:  SC_ACTION_RESTART,
        Delay: 1,
    }

    actions[1] = SC_ACTION{
        Type:  SC_ACTION_RESTART,
        Delay: 1,
    }

    actions[2] = SC_ACTION{
        Type:  SC_ACTION_RESTART,
        Delay: 1,
    }

    info := SERVICE_FAILURE_ACTIONS{
        ResetPeriod:  86400,
        RebootMsg:    0,
        Command:      0,
        ActionsCount: 3,
        Actions:      uintptr(unsafe.Pointer(&actions)),
    }

    ret, _, err := svcChangeServiceConfig2.Call(
        uintptr(handle),
        SERVICE_CONFIG_FAILURE_ACTIONS,
        uintptr(unsafe.Pointer(&info)),
    )

    if uint32(ret) == 0 {
        return err
    }

    return nil
}
