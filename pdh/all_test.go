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

package pdh

// Stdlib imports.
import(
    "syscall"
    "testing"
    "time"
)

const (
    wildcardPath = "\\Processor(*)\\% Processor Time"
)


func TestCounterCollection(t *testing.T) {
    query, err := PdhOpenQuery()
    checkErr(err, "PdhOpenQuery", t)
    t.Log("Query opened...")

    counters   := make(map[string]*syscall.Handle, 0)
    paths, err := PdhExpandCounterPath(wildcardPath)
    checkErr(err, "PdhExpandCounterPath", t)

    for i := range paths {
        newCounter, err := PdhAddCounter(query, paths[i])
        checkErr(err, "PdhAddCounter", t)
        t.Logf("Counter \"%s\" added...\n", paths[i])

        counters[paths[i]] = newCounter
    }

    for i := 0; i < 2; i++ {
        err = PdhCollectQueryData(query)
        checkErr(err, "PdhCollectQueryData", t)
        t.Log("Collected query data...")

        <-time.After(2 * time.Second)
    }

    for k, _ := range counters {
        val, err := PdhGetFormattedCounterValue(counters[k])
        checkErr(err, "PdhGetFormattedCounterVal", t)
        t.Logf("Counter %s val: %f", k, val.Value)
    }

    for k, _ := range counters {
        err = PdhRemoveCounter(counters[k])
        checkErr(err, "PdhRemoveCounter", t)
        t.Logf("Removed counter %s...\n", k)
    }

    err = PdhCloseQuery(query)
    checkErr(err, "PdhCloseQuery", t)
    t.Log("Closed query...")
}

func TestGetDllVersion(t *testing.T) {
    ver, err := PdhGetDllVersion()
    if err != nil {
        t.Fatalf("PdhGetDllVersion returned error code %#x\n", err)
    }

    t.Logf("PdhDll version %d\n", ver)
}

func checkErr(err error, testName string, t *testing.T) {
    if err != nil {
        t.Fatalf("%s returned error code %#x\n", testName, err)
    }
}
