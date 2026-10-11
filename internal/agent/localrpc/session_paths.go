package localrpc

// Packaged session-helper socket. The directory is root:root 0755 and the
// socket 0666; the executor authorizes every caller by SO_PEERCRED and its
// active logind graphical session, never by filesystem permissions alone.
const (
	DefaultSessionRuntimeDirectory = "/run/lindm-session"
	SessionSocketName              = "session.sock"
	DefaultSessionSocketPath       = DefaultSessionRuntimeDirectory + "/" + SessionSocketName
	// SessionBaseURL is the unresolved Connect base URL for the session socket.
	SessionBaseURL = "http://lindm-session.invalid"
)
