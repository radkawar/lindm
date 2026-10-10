//go:build linux

package nativehelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// Launch starts one fixed helper unit. authorize is invoked only after the helper
// reports that its native preconditions passed; it consumes the signed start and
// returns the exact boot-bound deadline. No package work is replayed on failure.
func Launch(ctx context.Context, stateDirectory, actionID string, input *agentv1.NativePackageTransactionRequest, authorize func(context.Context) (*agentv1.NativeEffectPermit, error)) (resultErr error) {
	request := proto.CloneOf(input)
	if request == nil {
		return errors.New("package_helper_request_required")
	}
	phase, err := phaseName(request.GetOperation())
	if err != nil {
		return err
	}
	if phase != "apply" {
		return errors.New("package_helper_staging_requires_async_stage")
	}
	if authorize == nil {
		return errors.New("package_helper_authority_required")
	}
	directory, err := transactionDirectory(stateDirectory, request.GetTransactionId())
	if err != nil {
		return err
	}
	request.ActionId = actionID
	request.Nonce = make([]byte, 32)
	if _, err := rand.Read(request.Nonce); err != nil {
		return err
	}
	encoded, err := encodeRecord(request)
	if err != nil {
		return err
	}
	defer clear(encoded)
	return launchEffect(ctx, directory, unitName(request.GetTransactionId(), phase), encoded, request.GetNonce(),
		transientProperties(directory, request.GetTransactionId(), phase), authorize, nil)
}

func launchEffect(ctx context.Context, directory, unit string, encoded, nonce []byte, properties []unitProperty, authorize func(context.Context) (*agentv1.NativeEffectPermit, error), output *agentv1.NativeHelperResult) (resultErr error) {
	if os.Geteuid() != 0 || authorize == nil {
		return errors.New("native_helper_root_authority_required")
	}
	ctx, cancel := context.WithTimeout(ctx, transactionTimeout)
	defer cancel()
	const phase = "apply"
	requestHash := sha256.Sum256(encoded)
	if err := writeProtected(directory, phase+"-request.pb", encoded); err != nil {
		return err
	}
	socketPath := filepath.Join(directory, phase+"-control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, listener.Close()) }()
	if err := os.Chmod(socketPath, 0600); err != nil {
		return err
	}
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	bus, err := openBus(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, bus.close()) }()
	if err := bus.startUnit(ctx, unit, properties); err != nil {
		return err
	}
	authorized := false
	defer func() {
		if !authorized && resultErr != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resultErr = errors.Join(resultErr, bus.stop(cleanup, unit))
		}
	}()
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	connection, err := listener.AcceptUnix()
	stopAccept()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close()) }()
	if err := requireRootPeer(connection); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopConnection()
	message, err := receiveMessage(connection)
	if err != nil {
		return err
	}
	if message.GetReady() != nil {
		ready := message.GetReady()
		if !bytes.Equal(ready.GetRequestSha256(), requestHash[:]) || !bytes.Equal(ready.GetNonce(), nonce) {
			return errors.New("package_helper_ready_binding")
		}
		permit, err := authorize(ctx)
		if err != nil {
			return err
		}
		// The durable signed grant is already consumed. Failure to deliver the
		// permit or receive completion is uncertain, never permission to replay.
		authorized = true
		permit = proto.CloneOf(permit)
		if permit == nil {
			return errors.New("package_helper_missing_permit")
		}
		permit.RequestSha256 = bytes.Clone(requestHash[:])
		permit.Nonce = bytes.Clone(nonce)
		if err := sendMessage(connection, &agentv1.NativeHelperMessage{Message: &agentv1.NativeHelperMessage_Permit{Permit: permit}}); err != nil {
			return err
		}
		message, err = receiveMessage(connection)
		if err != nil {
			return err
		}
	}
	result := message.GetResult()
	if result == nil || !bytes.Equal(result.GetRequestSha256(), requestHash[:]) || !bytes.Equal(result.GetNonce(), nonce) {
		return errors.New("package_helper_result_binding")
	}
	retained := new(agentv1.NativeHelperResult)
	if err := readRecordInto(directory, phase+"-result.pb", retained); err != nil {
		return err
	}
	if !proto.Equal(retained, result) {
		return errors.New("package_helper_retained_result_mismatch")
	}
	if authorized && result.GetOutcome() == agentv1.NativeHelperOutcome_NATIVE_HELPER_OUTCOME_SUCCEEDED {
		if output != nil {
			proto.Merge(output, result)
		}
		return nil
	}
	return fmt.Errorf("native package helper did not complete: %s", result.GetReason())
}
