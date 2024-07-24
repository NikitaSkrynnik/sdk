package asyncclose

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/tools/extend"
	"google.golang.org/protobuf/types/known/emptypb"
)

type asyncServer struct {
}

func NewServer() networkservice.NetworkServiceServer {
	return &asyncServer{}
}

func (t *asyncServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	return next.Server(ctx).Request(ctx, request)
}

func (t *asyncServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	var err error
	done := make(chan struct{})
	go func() {
		closeCtx = extend.WithValuesFromContext(closeCtx, ctx)
		_, err = next.Server(ctx).Close(closeCtx, conn)
		fmt.Println("close(done)")
		close(done)
		cancel()
	}()

	select {
	case <-ctx.Done():
		fmt.Println("<-ctx.Done()")

		select {
		case <-done:
			fmt.Println("case <-done")
			return &emptypb.Empty{}, err
		default:
			return &emptypb.Empty{}, ctx.Err()
		}
	case <-done:
		fmt.Println("<-done")
		return &emptypb.Empty{}, err
	}
}
