package modsecurity

import (
	"fmt"

	"gitlab.com/torrentalle/go-modsecurity/release"
)

// ModSecurity is a open source, cross platform web application firewall
type ModSecurity struct {
	connector string
}

// Phase consists in mapping the different stages of a given request.
// ModSecurity is expected to inspect data based on those "phases".
// If your module/application use this in a different order, it
// will lead ModSecurity to act in an unexpected behavior.
// It is mandatory to call all the phases, even if you don't have this
// phases segmented in your end.
type Phase int

const (
	// ConnectionPhase is the very first information that ModSecurity can
	// inspect. It is expected to happens before the virtual host name be
	// resolved. This phase is expected to happen immediately after a
	// connection is established.
	ConnectionPhase Phase = iota

	// URIPhase happens just after the web server (or any other application
	// that you may use with ModSecurity) have the acknowledgement
	// of the full request URI.
	URIPhase

	// RequestHeadersPhase happens when the server has all the information
	// about the headers. Notice however, that it is expected to happen prior
	// to the reception of the request body (if any).
	RequestHeadersPhase

	// RequestBodyPhase is expected to inspect the content of a request body,
	// that does not happens when the server has all the content but prior to that,
	// when the body transmission started.
	// ModSecurity can ask the webserver to block (or make any other disruptive action)
	// while the client is still transmitting the data.
	RequestBodyPhase

	// ResponseHeadersPhase happens just before all the response headers are
	// ready to be delivery to the client
	ResponseHeadersPhase

	// ResponseBodyPhase same as "RequestBodyPhase" perform a stream inspection
	// which may result in a disruptive action.
	ResponseBodyPhase

	// LoggingPhase is the last phase is the logging phase. At this phase ModSecurity
	// will generate the internal logs, there is no need to hold the request at
	// this point as this phase does not produce any kind of action.
	LoggingPhase

	// numberOfPhases just a marking for the expected number of phases.
	numberOfPhases
)

// LogProperty are properties used to configure the general log callback.
type LogProperty int

const (
	// TextLogProperty is Original ModSecurity text log entry.
	// The same entry that can be found within the Apache error_log (in the 2.x family)
	TextLogProperty LogProperty = 1

	// RuleMessageLogProperty Instead of return the text log entry an
	// instance of the class RuleMessages is returned.
	RuleMessageLogProperty LogProperty = 2

	// IncludeFullHighlightLogProperty only makes sense with the utilization of the
	// RuleMessageLogProperty. Without this property set the RuleMessage structure
	// will not be filled with the information of the hightlight.
	IncludeFullHighlightLogProperty LogProperty = 4
)

// NewModSecurity creates new ModSecurity instance
func NewModSecurity() *ModSecurity {
	return &ModSecurity{}
}

// WhoAmI return information about this ModSecurity version and platform.
// Platform and version are two questions that community will ask prior to
// provide support. Making it available internally and to the connector as well.
// Note: This information maybe will be used by a log parser. If you want to
//       update it, make it in a fashion that won't break the existent parsers.
//       (e.g. adding extra information _only_ to the end of the string)
func (msc *ModSecurity) WhoAmI() string {
	versionFmt := "goModSecurity v%s (%s)"
	return fmt.Sprintf(versionFmt, release.Version, release.Platform)
}

// ConnectorInformation returns the connector informationthat was set by
// 'setConnectorInformation'. Check setConnectorInformation documentation
// to understand the expected format.
func (msc *ModSecurity) ConnectorInformation(connector string) string {
	return msc.connector
}

// SetConnectorInformation set information about the connector that is using the library.
// For the purpose of log it is necessary for modsecurity to understand which 'connector'
// is consuming the API.
// It is strongly recommended to set a information in the following pattern:
//   ConnectorName vX.Y.Z-tag (something else)
func (msc *ModSecurity) SetConnectorInformation(connector string) {
	msc.connector = connector
}
