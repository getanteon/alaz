package ebpf

import "testing"

func TestParseSSLLibRemoveDuplicates(t *testing.T) {
	// expected one lib, libssl3.so (remoeved duplicates)
	text := `7f96bb1cf000-7f96bb22b000 r-xp 00000000 103:01 2202604                   /usr/lib64/libssl3.so
	7f96bb22b000-7f96bb42a000 ---p 0005c000 103:01 2202604                   /usr/lib64/libssl3.so
	7f96bb42a000-7f96bb42e000 r--p 0005b000 103:01 2202604                   /usr/lib64/libssl3.so
	7f96bb42e000-7f96bb42f000 rw-p 0005f000 103:01 2202604                   /usr/lib64/libssl3.so`

	libs, err := parseSSLlib(text)
	if err != nil {
		t.Fatal(err)
	}

	if len(libs) != 1 {
		t.Fatalf("expected 1 lib, got %d", len(libs))
	}

	lib := libs["/usr/lib64/libssl3.so"]
	if lib.version != "3" {
		t.Fatalf("expected version 3, got %s", lib.version)
	}
}

func TestParseSSLLib(t *testing.T) {
	text := `/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/lib/libssl.so.1.1
	/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/lib/libssl.so.1.1
	/lib/libssl.so.3
	/usr/local/lib/python3.9/site-packages/psycopg2_binary.libs/libssl-0331cfe8.so.1.1
	/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k (deleted)
	/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k (deleted)
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/usr/local/lib/python3.9/site-packages/psycopg2_binary.libs/libssl-0331cfe8.so.1.1
	/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k (deleted)
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k (deleted)
	/usr/lib64/libssl.so.1.0.2k
	/usr/lib/x86_64-linux-gnu/libssl.so.1.1
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	/usr/lib/x86_64-linux-gnu/libssl.so.3
	/usr/lib64/libssl3.so
	/usr/lib64/libssl.so.1.0.2k
	`

	libs, err := parseSSLlib(text)

	if err != nil {
		t.Fatal(err)
	}

	// /usr/lib/x86_64-linux-gnu/libssl.so.1.1
	// /usr/lib64/libssl3.so
	// /usr/lib64/libssl.so.1.0.2k
	// /lib/libssl.so.1.1
	// /lib/libssl.so.3
	// /usr/local/lib/python3.9/site-packages/psycopg2_binary.libs/libssl-0331cfe8.so.1.1
	// /usr/lib/x86_64-linux-gnu/libssl.so.3

	if len(libs) != 7 {
		t.Fatalf("expected 7 libs, got %d", len(libs))
	}

	lib := libs["/usr/lib/x86_64-linux-gnu/libssl.so.1.1"]
	if lib.version != "1.1" {
		t.Fatalf("expected version 1.1, got %s", lib.version)
	}

	lib = libs["/usr/lib64/libssl3.so"]
	if lib.version != "3" {
		t.Fatalf("expected version 3, got %s", lib.version)
	}

	lib = libs["/usr/lib64/libssl.so.1.0.2k"]
	if lib.version != "1.0.2" {
		t.Fatalf("expected version 1.0.2, got %s", lib.version)
	}

	lib = libs["/lib/libssl.so.1.1"]
	if lib.version != "1.1" {
		t.Fatalf("expected version 1.1, got %s", lib.version)
	}

	lib = libs["/lib/libssl.so.3"]
	if lib.version != "3" {
		t.Fatalf("expected version 3, got %s", lib.version)
	}

	lib = libs["/usr/local/lib/python3.9/site-packages/psycopg2_binary.libs/libssl-0331cfe8.so.1.1"]
	if lib.version != "1.1" {
		t.Fatalf("expected version 1.1, got %s", lib.version)
	}

	lib = libs["/usr/lib/x86_64-linux-gnu/libssl.so.3"]
	if lib.version != "3" {
		t.Fatalf("expected version 3, got %s", lib.version)
	}

}
