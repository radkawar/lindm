package core

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	enrollmentv1 "lindm/gen/lindm/enrollment/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/rpcreason"
	"lindm/internal/trust"
)

func (s *Service) RetrieveIssuance(ctx context.Context, req *connect.Request[enrollmentv1.RetrieveIssuanceRequest]) (*connect.Response[enrollmentv1.RetrieveIssuanceResponse], error) {
	ctx, cancel := Bound(ctx)
	defer cancel()
	if err := s.Acquire(ctx); err != nil {
		return nil, MapErr(err)
	}
	defer s.Release()
	denied := rpcreason.Error(connect.CodeUnauthenticated, "unauthenticated")
	if req.Msg == nil || !ValidAuthorityProof(req.Msg.GetAuthorityProof()) {
		return nil, denied
	}
	// These untrusted selectors locate only an existing receipt. They confer
	// no authority and never select verification keys from request material.
	var envelope dsse.Envelope
	if err := json.Unmarshal(req.Msg.GetAuthorityProof(), &envelope); err != nil || envelope.PayloadType != trust.RetrievalType {
		return nil, denied
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, denied
	}
	selector := new(agentv1.IssuanceRetrieval)
	if err := proto.Unmarshal(payload, selector); err != nil || selector.GetDeploymentId() != s.DeploymentID.String() {
		return nil, denied
	}
	deviceID, err := ParseUUID(selector.GetDeviceId())
	if err != nil {
		return nil, denied
	}
	generationID, err := ParseUUID(selector.GetEnrollmentGeneration())
	if err != nil {
		return nil, denied
	}
	requestID, err := ParseUUID(selector.GetIssuanceRequestId())
	if err != nil {
		return nil, denied
	}
	var response *enrollmentv1.RetrieveIssuanceResponse
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		row, err := q.GetDeviceForUpdate(ctx, deviceID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return denied
			}
			return err
		}
		if (row.State != StatePending && row.State != StateActive) || row.CurrentGenerationID == nil || *row.CurrentGenerationID != generationID {
			return denied
		}
		generation, err := q.GetGenerationAuthority(ctx, generationID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return denied
			}
			return err
		}
		if generation.DeviceID != deviceID || (generation.State != StatePending && generation.State != StateActive) {
			return denied
		}
		receipt, err := q.GetRenewalReceipt(ctx, devicedb.GetRenewalReceiptParams{GenerationID: generationID, RequestID: requestID})
		if err != nil {
			if err == pgx.ErrNoRows {
				return denied
			}
			return err
		}
		certificate, err := q.GetCertificateByID(ctx, receipt.IssuedCertificateID)
		if err != nil {
			if err == pgx.ErrNoRows {
				return denied
			}
			return err
		}
		if certificate.DeviceID != deviceID || certificate.GenerationID != generationID {
			return denied
		}
		block, rest := pem.Decode([]byte(certificate.Pem))
		if block == nil || block.Type != "CERTIFICATE" || len(bytesTrimSpace(rest)) != 0 {
			return denied
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return denied
		}
		publicKey, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok {
			return denied
		}
		claim := new(agentv1.IssuanceRetrieval)
		if err := s.Authority.Verify(ctx, req.Msg.GetAuthorityProof(), claim, 1, publicKey); err != nil {
			return denied
		}
		if !proto.Equal(selector, claim) || !s.AuthorityBinding(claim.GetDeploymentId(), claim.GetDeviceId(), claim.GetEnrollmentGeneration(), DevicePrincipal{DeviceID: deviceID, GenerationID: generationID}) || !EnrollmentIssuanceResumable(certificate, s.Now()) {
			return denied
		}
		expires, _ := FiniteTime(certificate.NotAfter)
		response = &enrollmentv1.RetrieveIssuanceResponse{CertificatePem: []byte(certificate.Pem), ExpiresAt: timestamppb.New(expires)}
		return nil
	})
	if err != nil {
		return nil, MapErr(err)
	}
	return NoStore(response), nil
}
