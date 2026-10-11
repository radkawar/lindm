// Package osupdate is the root runner behind the packaged
// lindm-os-update{,-now,-status}.service units (`lindm-agent os-update
// run|run-now|status`). It drives the distribution's own update tooling:
// unattended-upgrade plus needrestart on Ubuntu 24.04, dnf5 on Fedora 44 and
// dnf-automatic on RHEL 9. It records a bounded run summary and an offline
// patch-status observation.
//
// Non-goals: it renders no timer and owns no policy file; both belong to the
// os.update.v1 resource provider. It adds no repository, disables no
// signature check, never kills a running native transaction at the window
// end, and never replaces a logind shutdown schedule owned by someone else.
package osupdate
