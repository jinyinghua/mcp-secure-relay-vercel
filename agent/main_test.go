package main

import (
    "testing"
    "time"
)

func TestInside(t *testing.T) {
    cases := []struct { target string; want bool }{
        {"/srv/root/file.txt", true},
        {"/srv/root/nested/file.txt", true},
        {"/srv/root", true},
        {"/srv/root-other/file.txt", false},
        {"/srv/root/../outside", false},
    }
    for _, test := range cases {
        if got := inside("/srv/root", test.target); got != test.want {
            t.Errorf("inside(%q) = %v, want %v", test.target, got, test.want)
        }
    }
}

func TestLimitedBuffer(t *testing.T) {
    buffer := &limitedBuffer{limit: 3}
    _, _ = buffer.Write([]byte("abcdef"))
    if buffer.String() != "abc" || !buffer.truncated {
        t.Fatalf("got %q truncated=%v", buffer.String(), buffer.truncated)
    }
}

func TestArbitraryShellCommand(t *testing.T) {
    instance := &app{config: config{RootDir: t.TempDir(), MaxOutputBytes: 1024, MaxCommandSeconds: 2}}
    result, relayErr := instance.runCommand("printf 'hello' | tr a-z A-Z", 1)
    if relayErr != nil { t.Fatalf("runCommand failed: %v", relayErr) }
    if result["exitCode"] != 0 || result["stdoutBase64"] != "SEVMTE8=" {
        t.Fatalf("unexpected command result: %#v", result)
    }
}

func TestCommandTimeout(t *testing.T) {
    instance := &app{config: config{RootDir: t.TempDir(), MaxOutputBytes: 1024, MaxCommandSeconds: 1}}
    started := time.Now()
    _, relayErr := instance.runCommand("sleep 2", 1)
    if relayErr == nil || relayErr.Code != "COMMAND_TIMEOUT" {
        t.Fatalf("expected timeout, got %#v", relayErr)
    }
    if time.Since(started) > 2500*time.Millisecond {
        t.Fatal("command timeout was not applied")
    }
}
