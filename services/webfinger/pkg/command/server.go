package command

import (
	"context"
	"fmt"

	"github.com/oklog/run"
	"github.com/owncloud/ocis/v2/ocis-pkg/config/configlog"
	"github.com/owncloud/ocis/v2/ocis-pkg/tracing"
	"github.com/owncloud/ocis/v2/ocis-pkg/version"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/config"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/config/parser"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/logging"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/metrics"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/relations"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/server/debug"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/server/http"
	"github.com/owncloud/ocis/v2/services/webfinger/pkg/service/v0"
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

			var (
				gr          = run.Group{}
				ctx, cancel = context.WithCancel(c.Context)
				m           = metrics.New(metrics.Logger(logger))
			)

			defer cancel()

			m.BuildInfo.WithLabelValues(version.GetString()).Set(1)

			{
				relationProviders, err := getRelationProviders(cfg)
				if err != nil {
					logger.Error().Err(err).Msg("relation provider init")
					return err
				}

				svc, err := service.New(
					service.Logger(logger),
					service.Config(cfg),
					service.WithRelationProviders(relationProviders),
				)
				if err != nil {
					logger.Error().Err(err).Msg("handler init")
					return err
				}
				svc = service.NewInstrument(svc, m)
				svc = service.NewLogging(svc, logger) // this logs service specific data
				svc = service.NewTracing(svc, traceProvider)

				server, err := http.Server(
					http.Logger(logger),
					http.Context(ctx),
					http.Config(cfg),
					http.Service(svc),
					http.TraceProvider(traceProvider),
				)

				if err != nil {
					logger.Info().
						Err(err).
						Str("server", "http").
						Msg("Failed to initialize server")

					return err
				}

				gr.Add(func() error {
					return server.Run()
				}, func(err error) {
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
			}

			{
				debugServer, err := debug.Server(
					debug.Logger(logger),
					debug.Context(ctx),
					debug.Config(cfg),
				)

				if err != nil {
					logger.Info().Err(err).Str("transport", "debug").Msg("Failed to initialize server")
					return err
				}

				gr.Add(debugServer.ListenAndServe, func(err error) {
					_ = debugServer.Shutdown(ctx)
					cancel()
				})
			}

			return gr.Run()
		},
	}
}

func getRelationProviders(cfg *config.Config) (map[string]service.RelationProvider, error) {
	rels := map[string]service.RelationProvider{}
	for _, relationURI := range cfg.Relations {
		switch relationURI {
		case relations.OpenIDConnectRel:
			rels[relationURI] = relations.OpenIDDiscovery(cfg.IDP)
		case relations.OwnCloudInstanceRel:
			var err error
			rels[relationURI], err = relations.OwnCloudInstance(cfg.Instances, cfg.OcisURL)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown relation '%s'", relationURI)
		}
	}
	return rels, nil
}
