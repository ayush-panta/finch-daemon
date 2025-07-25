// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package builder comprises functions, interfaces and structures related to build APIs
package builder

import (
	"context"
	"io"
	"net/http"

	ncTypes "github.com/containerd/nerdctl/v2/pkg/api/types"
	"github.com/containerd/nerdctl/v2/pkg/config"

	"github.com/runfinch/finch-daemon/api/types"
	"github.com/runfinch/finch-daemon/internal/backend"
	"github.com/runfinch/finch-daemon/pkg/credential"
	"github.com/runfinch/finch-daemon/pkg/flog"
)

// RegisterHandlers register all the supported endpoints related to the container APIs.
func RegisterHandlers(r types.VersionedRouter,
	service Service,
	conf *config.Config,
	logger flog.Logger,
	ncBuildSvc backend.NerdctlBuilderSvc,
	credService *credential.CredentialService,
) {
	h := newHandler(service, conf, logger, ncBuildSvc, credService)
	r.HandleFunc("/build", h.build, http.MethodPost)
}

// Service interface for build related APIs
//
//go:generate mockgen --destination=../../../mocks/mocks_builder/buildersvc.go -package=mocks_builder github.com/runfinch/finch-daemon/api/handlers/builder Service
type Service interface {
	Build(ctx context.Context, options *ncTypes.BuilderBuildOptions, tarBody io.ReadCloser, buildID string) ([]types.BuildResult, error)
}

// newHandler creates the handler that serves all the container related APIs.
func newHandler(service Service, conf *config.Config, logger flog.Logger, ncBuildSvc backend.NerdctlBuilderSvc, credService *credential.CredentialService) *handler {
	return &handler{
		service:       service,
		Config:        conf,
		logger:        logger,
		ncBuildSvc:    ncBuildSvc,
		credentialSvc: credService,
	}
}

type handler struct {
	service       Service
	Config        *config.Config
	logger        flog.Logger
	ncBuildSvc    backend.NerdctlBuilderSvc
	credentialSvc *credential.CredentialService
}
