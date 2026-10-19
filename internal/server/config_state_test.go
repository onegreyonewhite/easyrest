package server

import "testing"

func TestSetupApplication_ReplacesPort(t *testing.T) {
	orig := GetConfig()
	t.Cleanup(func() { SetConfig(orig) })

	if err := SetupApplication("port: \"1111\"\n", nil); err != nil {
		t.Fatal(err)
	}
	if got := GetConfig().Port; got != "1111" {
		t.Fatalf("port after first setup: %s", got)
	}
	if err := SetupApplication("port: \"2222\"\n", nil); err != nil {
		t.Fatal(err)
	}
	if got := GetConfig().Port; got != "2222" {
		t.Fatalf("port after second setup: %s", got)
	}
}
