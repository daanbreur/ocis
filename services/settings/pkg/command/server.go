package command

import (
	"context"
	"fmt"

	"github.com/oklog/run"
	"github.com/owncloud/ocis/v2/ocis-pkg/config/configlog"
	ogrpc "github.com/owncloud/ocis/v2/ocis-pkg/service/grpc"
	"github.com/owncloud/ocis/v2/ocis-pkg/tracing"
	"github.com/owncloud/ocis/v2/ocis-pkg/version"
	"github.com/owncloud/ocis/v2/services/settings/pkg/config"
	"github.com/owncloud/ocis/v2/services/settings/pkg/config/parser"
	"github.com/owncloud/ocis/v2/services/settings/pkg/logging"
	"github.com/owncloud/ocis/v2/services/settings/pkg/metrics"
	"github.com/owncloud/ocis/v2/services/settings/pkg/server/debug"
	"github.com/owncloud/ocis/v2/services/settings/pkg/server/grpc"
	"github.com/owncloud/ocis/v2/services/settings/pkg/server/http"
	svc "github.com/owncloud/ocis/v2/services/settings/pkg/service/v0"
	"github.com/urfave/cli/v2"
)

// Server is the entrypoint for the server command.
func Server(cfg *config.Config) *cli.Command {
	return &cli.Command{
		Name:     "server",
		Usage:    fmt.Sprintf("start the %s service without runtime (unsupervised mode)", cfg.Service.Name),
		Category: "server",
		Before: func(c *cli.Context) error {
			return configlog.ReturnFatal(parser.ParseConfig(cfg))
		},
		Action: func(c *cli.Context) error {
			logger := logging.Configure(cfg.Service.Name, cfg.Log)
			traceProvider, err := tracing.GetServiceTraceProvider(cfg.Tracing, cfg.Service.Name)
			if err != nil {
				return err
			}
			cfg.GrpcClient, err = ogrpc.NewClient(
				append(ogrpc.GetClientOptions(cfg.GRPCClientTLS), ogrpc.WithTraceProvider(traceProvider))...,
			)
			if err != nil {
				return err
			}

			servers := run.Group{}
			ctx, cancel := context.WithCancel(c.Context)
			defer cancel()

			mtrcs := metrics.New()
			mtrcs.BuildInfo.WithLabelValues(version.GetString()).Set(1)

			handle := svc.NewDefaultLanguageService(cfg, svc.NewService(cfg, logger))

			// prepare an HTTP server and add it to the group run.
			httpServer, err := http.Server(
				http.Name(cfg.Service.Name),
				http.Logger(logger),
				http.Context(ctx),
				http.Config(cfg),
				http.Metrics(mtrcs),
				http.ServiceHandler(handle),
				http.TraceProvider(traceProvider),
			)
			if err != nil {
				logger.Error().
					Err(err).
					Msg("Error initializing http service")
				return fmt.Errorf("could not initialize http service: %w", err)
			}
			servers.Add(httpServer.Run, func(err error) {
				if err == nil {
					logger.Info().
						Str("transport", "http").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				} else {
					logger.Error().Err(err).
						Str("transport", "http").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				}

				cancel()
			})

			// prepare a gRPC server and add it to the group run.
			grpcServer := grpc.Server(
				grpc.Name(cfg.Service.Name),
				grpc.Logger(logger),
				grpc.Context(ctx),
				grpc.Config(cfg),
				grpc.Metrics(mtrcs),
				grpc.ServiceHandler(handle),
				grpc.TraceProvider(traceProvider),
			)
			servers.Add(grpcServer.Run, func(_ error) {
				if err == nil {
					logger.Info().
						Str("transport", "grpc").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				} else {
					logger.Error().Err(err).
						Str("transport", "grpc").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				}

				cancel()
			})

			// prepare a debug server and add it to the group run.
			debugServer, err := debug.Server(
				debug.Logger(logger),
				debug.Context(ctx),
				debug.Config(cfg),
			)
			if err != nil {
				logger.Error().Err(err).Str("server", "debug").Msg("Failed to initialize server")
				return err
			}

			servers.Add(debugServer.ListenAndServe, func(_ error) {
				_ = debugServer.Shutdown(ctx)
				cancel()
			})

			return servers.Run()
		},
	}
}
