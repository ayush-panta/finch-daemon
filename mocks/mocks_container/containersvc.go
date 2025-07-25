// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/runfinch/finch-daemon/api/handlers/container (interfaces: Service)
//
// Generated by this command:
//
//	mockgen --destination=../../../mocks/mocks_container/containersvc.go -package=mocks_container github.com/runfinch/finch-daemon/api/handlers/container Service
//

// Package mocks_container is a generated GoMock package.
package mocks_container

import (
	context "context"
	io "io"
	reflect "reflect"

	types "github.com/containerd/nerdctl/v2/pkg/api/types"
	types0 "github.com/runfinch/finch-daemon/api/types"
	gomock "go.uber.org/mock/gomock"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
	isgomock struct{}
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// Attach mocks base method.
func (m *MockService) Attach(ctx context.Context, cid string, opts *types0.AttachOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Attach", ctx, cid, opts)
	ret0, _ := ret[0].(error)
	return ret0
}

// Attach indicates an expected call of Attach.
func (mr *MockServiceMockRecorder) Attach(ctx, cid, opts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Attach", reflect.TypeOf((*MockService)(nil).Attach), ctx, cid, opts)
}

// Create mocks base method.
func (m *MockService) Create(ctx context.Context, image string, cmd []string, createOpt types.ContainerCreateOptions, netOpt types.NetworkOptions) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, image, cmd, createOpt, netOpt)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockServiceMockRecorder) Create(ctx, image, cmd, createOpt, netOpt any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockService)(nil).Create), ctx, image, cmd, createOpt, netOpt)
}

// ExecCreate mocks base method.
func (m *MockService) ExecCreate(ctx context.Context, cid string, config types0.ExecConfig) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExecCreate", ctx, cid, config)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExecCreate indicates an expected call of ExecCreate.
func (mr *MockServiceMockRecorder) ExecCreate(ctx, cid, config any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExecCreate", reflect.TypeOf((*MockService)(nil).ExecCreate), ctx, cid, config)
}

// ExtractArchiveInContainer mocks base method.
func (m *MockService) ExtractArchiveInContainer(ctx context.Context, putArchiveOpt *types0.PutArchiveOptions, body io.ReadCloser) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExtractArchiveInContainer", ctx, putArchiveOpt, body)
	ret0, _ := ret[0].(error)
	return ret0
}

// ExtractArchiveInContainer indicates an expected call of ExtractArchiveInContainer.
func (mr *MockServiceMockRecorder) ExtractArchiveInContainer(ctx, putArchiveOpt, body any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtractArchiveInContainer", reflect.TypeOf((*MockService)(nil).ExtractArchiveInContainer), ctx, putArchiveOpt, body)
}

// GetPathToFilesInContainer mocks base method.
func (m *MockService) GetPathToFilesInContainer(ctx context.Context, cid, path string) (string, func(), error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPathToFilesInContainer", ctx, cid, path)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(func())
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetPathToFilesInContainer indicates an expected call of GetPathToFilesInContainer.
func (mr *MockServiceMockRecorder) GetPathToFilesInContainer(ctx, cid, path any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPathToFilesInContainer", reflect.TypeOf((*MockService)(nil).GetPathToFilesInContainer), ctx, cid, path)
}

// Inspect mocks base method.
func (m *MockService) Inspect(ctx context.Context, cid string, size bool) (*types0.Container, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Inspect", ctx, cid, size)
	ret0, _ := ret[0].(*types0.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Inspect indicates an expected call of Inspect.
func (mr *MockServiceMockRecorder) Inspect(ctx, cid, size any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Inspect", reflect.TypeOf((*MockService)(nil).Inspect), ctx, cid, size)
}

// Kill mocks base method.
func (m *MockService) Kill(ctx context.Context, cid string, options types.ContainerKillOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Kill", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Kill indicates an expected call of Kill.
func (mr *MockServiceMockRecorder) Kill(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Kill", reflect.TypeOf((*MockService)(nil).Kill), ctx, cid, options)
}

// List mocks base method.
func (m *MockService) List(ctx context.Context, listOpts types.ContainerListOptions) ([]types0.ContainerListItem, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", ctx, listOpts)
	ret0, _ := ret[0].([]types0.ContainerListItem)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockServiceMockRecorder) List(ctx, listOpts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockService)(nil).List), ctx, listOpts)
}

// Logs mocks base method.
func (m *MockService) Logs(ctx context.Context, cid string, opts *types0.LogsOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logs", ctx, cid, opts)
	ret0, _ := ret[0].(error)
	return ret0
}

// Logs indicates an expected call of Logs.
func (mr *MockServiceMockRecorder) Logs(ctx, cid, opts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logs", reflect.TypeOf((*MockService)(nil).Logs), ctx, cid, opts)
}

// Pause mocks base method.
func (m *MockService) Pause(ctx context.Context, cid string, options types.ContainerPauseOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pause", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Pause indicates an expected call of Pause.
func (mr *MockServiceMockRecorder) Pause(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pause", reflect.TypeOf((*MockService)(nil).Pause), ctx, cid, options)
}

// Remove mocks base method.
func (m *MockService) Remove(ctx context.Context, cid string, force, removeVolumes bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", ctx, cid, force, removeVolumes)
	ret0, _ := ret[0].(error)
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockServiceMockRecorder) Remove(ctx, cid, force, removeVolumes any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockService)(nil).Remove), ctx, cid, force, removeVolumes)
}

// Rename mocks base method.
func (m *MockService) Rename(ctx context.Context, cid, newName string, opts types.ContainerRenameOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Rename", ctx, cid, newName, opts)
	ret0, _ := ret[0].(error)
	return ret0
}

// Rename indicates an expected call of Rename.
func (mr *MockServiceMockRecorder) Rename(ctx, cid, newName, opts any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rename", reflect.TypeOf((*MockService)(nil).Rename), ctx, cid, newName, opts)
}

// Restart mocks base method.
func (m *MockService) Restart(ctx context.Context, cid string, options types.ContainerRestartOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Restart", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Restart indicates an expected call of Restart.
func (mr *MockServiceMockRecorder) Restart(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Restart", reflect.TypeOf((*MockService)(nil).Restart), ctx, cid, options)
}

// Start mocks base method.
func (m *MockService) Start(ctx context.Context, cid string, options types.ContainerStartOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockServiceMockRecorder) Start(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockService)(nil).Start), ctx, cid, options)
}

// Stats mocks base method.
func (m *MockService) Stats(ctx context.Context, cid string) (<-chan *types0.StatsJSON, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stats", ctx, cid)
	ret0, _ := ret[0].(<-chan *types0.StatsJSON)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Stats indicates an expected call of Stats.
func (mr *MockServiceMockRecorder) Stats(ctx, cid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stats", reflect.TypeOf((*MockService)(nil).Stats), ctx, cid)
}

// Stop mocks base method.
func (m *MockService) Stop(ctx context.Context, cid string, option types.ContainerStopOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Stop", ctx, cid, option)
	ret0, _ := ret[0].(error)
	return ret0
}

// Stop indicates an expected call of Stop.
func (mr *MockServiceMockRecorder) Stop(ctx, cid, option any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockService)(nil).Stop), ctx, cid, option)
}

// Unpause mocks base method.
func (m *MockService) Unpause(ctx context.Context, cid string, options types.ContainerUnpauseOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unpause", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Unpause indicates an expected call of Unpause.
func (mr *MockServiceMockRecorder) Unpause(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unpause", reflect.TypeOf((*MockService)(nil).Unpause), ctx, cid, options)
}

// Wait mocks base method.
func (m *MockService) Wait(ctx context.Context, cid string, options types.ContainerWaitOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Wait", ctx, cid, options)
	ret0, _ := ret[0].(error)
	return ret0
}

// Wait indicates an expected call of Wait.
func (mr *MockServiceMockRecorder) Wait(ctx, cid, options any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Wait", reflect.TypeOf((*MockService)(nil).Wait), ctx, cid, options)
}

// WriteFilesAsTarArchive mocks base method.
func (m *MockService) WriteFilesAsTarArchive(filePath string, writer io.Writer, slashDot bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteFilesAsTarArchive", filePath, writer, slashDot)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteFilesAsTarArchive indicates an expected call of WriteFilesAsTarArchive.
func (mr *MockServiceMockRecorder) WriteFilesAsTarArchive(filePath, writer, slashDot any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteFilesAsTarArchive", reflect.TypeOf((*MockService)(nil).WriteFilesAsTarArchive), filePath, writer, slashDot)
}
