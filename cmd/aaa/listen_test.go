package main

import "testing"

func TestValidateListenAddressLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		if err := validateListenAddress(addr, false); err != nil {
			t.Fatalf("%s rejected: %v", addr, err)
		}
	}
}

func TestValidateListenAddressRejectsRemoteByDefault(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "192.0.2.10:8080", "[::]:8080"} {
		if err := validateListenAddress(addr, false); err == nil {
			t.Fatalf("%s accepted without allow-remote", addr)
		}
	}
}

func TestValidateListenAddressAllowsExplicitRemote(t *testing.T) {
	if err := validateListenAddress("0.0.0.0:8080", true); err != nil {
		t.Fatal(err)
	}
}

func TestValidateListenAddressRejectsMalformed(t *testing.T) {
	if err := validateListenAddress("127.0.0.1", false); err == nil {
		t.Fatal("malformed address accepted")
	}
}
