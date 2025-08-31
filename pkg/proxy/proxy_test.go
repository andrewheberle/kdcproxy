package proxy

import (
	"bytes"
	"testing"
)

func TestUnmarshalKerbLength(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    int
		wantErr bool
	}{
		{"nil slice", nil, 0, true},
		{"too short 1/4", []byte{0}, 0, true},
		{"too short 2/4", []byte{0, 0}, 0, true},
		{"too short 3/4", []byte{0, 0, 0}, 0, true},
		{"length == 0", []byte{0, 0, 0, 0}, 0, false},
		{"length == 1", []byte{0, 0, 0, 1}, 1, false},
		{"length == 257", []byte{0, 0, 1, 1}, 257, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalKerbLength(tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalKerbLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("UnmarshalKerbLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMarshalKerbLength(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want []byte
	}{
		{"zero length", 0, []byte{0, 0, 0, 0}},
		{"length == 1", 1, []byte{0, 0, 0, 1}},
		{"length == 257", 257, []byte{0, 0, 1, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MarshalKerbLength(tt.n)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MarshalKerbLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitKdcProxy_WithConfig(t *testing.T) {
	_, err := InitKdcProxy(WithConfig("missing.conf"))
	if err == nil {
		t.Errorf("expected error attempting to load missing config file, got nil")
	}
}
