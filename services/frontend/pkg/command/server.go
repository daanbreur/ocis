package command

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/cs3org/reva/v2/cmd/revad/runtime"
	"github.com/gofrs/uuid"
	"github.com/oklog/run"
	"github.com/urfave/cli/v2"

	"github.com/owncloud/ocis/v2/ocis-pkg/config/configlog"
	"github.com/owncloud/ocis/v2/ocis-pkg/registry"
	"github.com/owncloud/ocis/v2/ocis-pkg/tracing"
	"github.com/owncloud/ocis/v2/ocis-pkg/version"
	"github.com/owncloud/ocis/v2/services/frontend/pkg/config"
	"github.com/owncloud/ocis/v2/services/frontend/pkg/config/parser"
	"github.com/owncloud/ocis/v2/services/frontend/pkg/logging"
	"github.com/owncloud/ocis/v2/services/frontend/pkg/revaconfig"
	"github.com/owncloud/ocis/v2/services/frontend/pkg/server/debug"
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

			rCfg, err := revaconfig.FrontendConfigFromStruct(cfg, logger)
			if err != nil {
				return err
			}

			// make sure the run group executes all interrupt handlers when the context is canceled
			gr.Add(func() error {
				<-ctx.Done()
				return nil
			}, func(_ error) {
			})

			gr.Add(func() error {
				pidFile := path.Join(os.TempDir(), "revad-"+cfg.Service.Name+"-"+uuid.Must(uuid.NewV4()).String()+".pid")
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
				_ = debugServer.Shutdown(ctx)
				cancel()
			})

			httpSvc := registry.BuildHTTPService(cfg.HTTP.Namespace+"."+cfg.Service.Name, cfg.HTTP.Addr, version.GetString())
			if err := registry.RegisterService(ctx, logger, httpSvc, cfg.Debug.Addr); err != nil {
				logger.Fatal().Err(err).Msg("failed to register the http service")
			}

			// add event handler
			gr.Add(func() error {
				return ListenForEvents(ctx, cfg, logger)
			}, func(_ error) {
				cancel()
			})

			return gr.Run()
		},
	}
}
