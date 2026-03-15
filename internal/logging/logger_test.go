package logging

import "testing"

func TestGet_ReturnsNonNil(t *testing.T) {
	if Get() == nil {
		t.Fatal("Get() returned nil")
	}
}

func TestGet_ReturnsSingleton(t *testing.T) {
	a := Get()
	b := Get()
	if a != b {
		t.Error("Get() should return the same instance")
	}
}
