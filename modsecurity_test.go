package modsecurity

import (
	"runtime"
	"strings"
	"testing"
)

func TestModSecurity_WhoAmI(t *testing.T) {

	ver := "0.0.1-dev"

	msc := &ModSecurity{}
	got := msc.WhoAmI()

	if !strings.Contains(got, "v"+ver) {
		t.Errorf("ModSecurity.WhoAmI() must return Version string 'v%s', got '%s'", ver, got)
	}

	expectedPlatform := strings.Title(runtime.GOOS)
	if !strings.Contains(got, "("+expectedPlatform+")") {
		t.Errorf("ModSecurity.WhoAmI() must return Platform string '(%s)', got '%s'", expectedPlatform, got)
	}

}

func TestModSecurity_ConnectorInformation(t *testing.T) {
	connector := "test-connector"
	msc := &ModSecurity{}
	msc.SetConnectorInformation(connector)
	got := msc.ConnectorInformation()

	if got != connector {
		t.Errorf("ModSecurity.ConnectorInformation() must return '%s', got '%s'", connector, got)
	}

}
