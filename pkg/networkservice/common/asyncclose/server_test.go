package asyncclose_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/asyncclose"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/inject/injecterror"
	"github.com/stretchr/testify/require"
)

type waitServer struct {
	timeout time.Duration
}

func NewServer(timeout time.Duration) networkservice.NetworkServiceServer {
	return &waitServer{
		timeout: timeout,
	}
}

func (t *waitServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	time.Sleep(t.timeout)
	return next.Server(ctx).Request(ctx, request)
}

func (t *waitServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	time.Sleep(t.timeout)
	return next.Server(ctx).Close(ctx, conn)
}

func TestCloseDoneBeforeDealine(t *testing.T) {
	server := next.NewNetworkServiceServer(
		asyncclose.NewServer(),
		&waitServer{timeout: time.Second * 1},
	)

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	_, err := server.Close(closeCtx, &networkservice.Connection{})
	require.NoError(t, err)
}

func TestCloseDoneAfterDealine(t *testing.T) {
	server := next.NewNetworkServiceServer(
		asyncclose.NewServer(),
		&waitServer{timeout: time.Second * 20},
	)

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()
	_, err := server.Close(closeCtx, &networkservice.Connection{})
	fmt.Println(err.Error())
	require.Error(t, err)
}

func TestCloseAndDeadlineAtTheSameTime(t *testing.T) {
	server := next.NewNetworkServiceServer(
		asyncclose.NewServer(),
		&waitServer{timeout: time.Millisecond * 500},
		injecterror.NewServer(injecterror.WithError(errors.New("error"))),
	)

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)
	defer cancel()
	_, err := server.Close(closeCtx, &networkservice.Connection{})
	require.Error(t, err)
}
