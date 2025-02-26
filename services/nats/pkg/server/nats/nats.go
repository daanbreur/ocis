package nats

import (
	"context"
	"time"

	nserver "github.com/nats-io/nats-server/v2/server"
)

var NATSListenAndServeLoopTimer = 1 * time.Second

type NATSServer struct {
	ctx    context.Context
	server *nserver.Server
}

// NatsOption configures the new NATSServer instance
func NewNATSServer(ctx context.Context, logger nserver.Logger, opts ...NatsOption) (*NATSServer, error) {
	natsOpts := &nserver.Options{}

	for _, o := range opts {
		o(natsOpts)
	}

	// enable JetStream
	natsOpts.JetStream = true
	// The NATS server itself runs the signal handling. We set `natsOpts.NoSigs = true` because we want to handle signals ourselves
	natsOpts.NoSigs = true

	server, err := nserver.NewServer(natsOpts)
	if err != nil {
		return nil, err
	}

	server.SetLoggerV2(logger, true, true, false)

	return &NATSServer{
		ctx:    ctx,
		server: server,
	}, nil
}

// ListenAndServe runs the NATSServer in a blocking way until the server is shutdown or an error occurs
func (n *NATSServer) ListenAndServe() (err error) {
	go n.server.Start()
	<-n.ctx.Done()
	return nil
}

// Shutdown stops the NATSServer gracefully
func (n *NATSServer) Shutdown() {
	n.server.Shutdown()
	n.server.WaitForShutdown()
}
