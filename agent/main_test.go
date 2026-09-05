package main

import "testing"

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
