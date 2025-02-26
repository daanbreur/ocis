package command

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/cs3org/reva/v2/cmd/revad/runtime"
	"github.com/gofrs/uuid"
	"github.com/oklog/run"
	"github.com/owncloud/ocis/v2/ocis-pkg/config/configlog"
	"github.com/owncloud/ocis/v2/ocis-pkg/registry"
	"github.com/owncloud/ocis/v2/ocis-pkg/tracing"
	"github.com/owncloud/ocis/v2/ocis-pkg/version"
	"github.com/owncloud/ocis/v2/services/sharing/pkg/config"
	"github.com/owncloud/ocis/v2/services/sharing/pkg/config/parser"
	"github.com/owncloud/ocis/v2/services/sharing/pkg/logging"
	"github.com/owncloud/ocis/v2/services/sharing/pkg/revaconfig"
	"github.com/owncloud/ocis/v2/services/sharing/pkg/server/debug"
	"github.com/urfave/cli/v2"
)

// Server is the entry point for the server command.
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
			gr := run.Group{}
			ctx, cancel := context.WithCancel(c.Context)

			defer cancel()

			// precreate folders
			if cfg.UserSharingDriver == "json" && cfg.UserSharingDrivers.JSON.File != "" {
				if err := os.MkdirAll(filepath.Dir(cfg.UserSharingDrivers.JSON.File), os.FileMode(0700)); err != nil {
					return err
				}
			}
			if cfg.PublicSharingDriver == "json" && cfg.PublicSharingDrivers.JSON.File != "" {
				if err := os.MkdirAll(filepath.Dir(cfg.PublicSharingDrivers.JSON.File), os.FileMode(0700)); err != nil {
					return err
				}
			}

			// make sure the run group executes all interrupt handlers when the context is canceled
			gr.Add(func() error {
				<-ctx.Done()
				return nil
			}, func(_ error) {
			})

			gr.Add(func() error {
				pidFile := path.Join(os.TempDir(), "revad-"+cfg.Service.Name+"-"+uuid.Must(uuid.NewV4()).String()+".pid")
				rCfg, err := revaconfig.SharingConfigFromStruct(cfg, logger)
				if err != nil {
					return err
				}
				reg := registry.GetRegistry()

				runtime.RunWithOptions(rCfg, pidFile,
					runtime.WithLogger(&logger.Logger),
					runtime.WithRegistry(reg),
					runtime.WithTraceProvider(traceProvider),
				)

				return nil
			}, func(err error) {
				if err == nil {
					logger.Info().
						Str("transport", "reva").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				} else {
					logger.Error().Err(err).
						Str("transport", "reva").
						Str("server", cfg.Service.Name).
						Msg("Shutting down server")
				}

				cancel()
			})

			debugServer, err := debug.Server(
				debug.Logger(logger),
				debug.Context(ctx),
				debug.Config(cfg),
			)

			if err != nil {
				logger.Info().Err(err).Str("server", "debug").Msg("Failed to initialize server")
				return err
			}

			gr.Add(debugServer.ListenAndServe, func(_ error) {
				cancel()
			})

			grpcSvc := registry.BuildGRPCService(cfg.GRPC.Namespace+"."+cfg.Service.Name, cfg.GRPC.Protocol, cfg.GRPC.Addr, version.GetString())
			if err := registry.RegisterService(ctx, logger, grpcSvc, cfg.Debug.Addr); err != nil {
				logger.Fatal().Err(err).Msg("failed to register the grpc service")
			}

			return gr.Run()
		},
	}
}
