package secret

import "testing"

func TestSecret(t *testing.T) {
	if Hide("") != "" || Hide("pw") != Mask {
		t.Fatal("Hide")
	}
	if HideTail("123456:ABCDEFGHIJ") != Mask+"GHIJ" || HideTail("short") != Mask {
		t.Fatal("HideTail")
	}
	if Keep(Mask, "real") != "real" || Keep(Mask+"GHIJ", "real") != "real" || Keep(" pass ", "real") != " pass " || Keep("", "real") != "" {
		t.Fatal("Keep")
	}
}
