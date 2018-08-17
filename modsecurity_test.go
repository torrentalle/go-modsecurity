package modsecurity

import (
	"strings"
	"testing"

	"gitlab.com/torrentalle/go-modsecurity/release"
)

func TestModSecurity_WhoAmI(t *testing.T) {

	expectedVersion := release.Version

	msc := &ModSecurity{}
	got := msc.WhoAmI()

	if !strings.Contains(got, "v"+expectedVersion) {
		t.Errorf("ModSecurity.WhoAmI() must return Version string 'v%s', got '%s'", expectedVersion, got)
	}

	expectedPlatform := release.Platform
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
