package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/andrewheberle/configger"
	"github.com/andrewheberle/kdcproxy/pkg/proxy"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/oklog/run"
	sloghttp "github.com/samber/slog-http"
	"github.com/spf13/pflag"
)

func main() {
	// command line flags
	f := pflag.NewFlagSet("kdcproxy", pflag.ContinueOnError)
	f.String("listen", "127.0.0.1:8080", "Service listen address")
	f.String("cert", "", "TLS certificate")
	f.String("key", "", "TLS key")
	f.String("krb5conf", "", "Path to krb5.conf")
	f.Int("rate", proxy.DefaultRateLimit, "Requests per second to the KDC allowed")

	// logging
	logLevel := new(slog.LevelVar)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// parse flags
	if err := f.Parse(os.Args[1:]); err != nil {
		logger.Error("command line parsing error", "error", err)
		os.Exit(1)
	}

	// grab config from flags and env vars
	config, err := configger.LoadConfig(f, configger.WithoutConfigurationFile(), configger.WithEnvPrefix("kdc_proxy"))
	if err != nil {
		logger.Error("command line parsing error", "error", err)
		os.Exit(1)
	}

	// set up kdc proxy
	opts := []proxy.ProxyOption{
		proxy.WithLimit(config.Int("rate")),
	}
	if config := config.String("krb5conf"); config != "" {
		opts = append(opts, proxy.WithConfig(config))
	}
	k, err := proxy.InitKdcProxy(opts...)
	if err != nil {
		logger.Error("could not set up kdc proxy", "error", err)
		os.Exit(1)
	}

	// add to http service
	mux := http.NewServeMux()
	mux.HandleFunc("/KdcProxy", k.Handler)
	mux.Handle("/metrics", k.Metrics())

	// set up logged handler
	handler := recovery(logger)(mux)
	handler = sloghttp.New(logger)(handler)

	// run group
	g := run.Group{}

	// start server
	if config.String("cert") != "" && config.String("key") != "" {
		// logging about command line
		logger.Info("setting up tls server",
			"cert", config.String("cert"),
			"key", config.String("key"),
		)

		certctx, certcancel := context.WithCancel(context.Background())

		certinel, err := fswatcher.New(config.String("cert"), config.String("key"))
		if err != nil {
			logger.Error("unable to read server certificate", "error", err)
			os.Exit(1)
		}

		// set up server
		srv := newServer(config.String("listen"), handler, certinel)

		// add certinel
		g.Add(func() error {
			return certinel.Start(certctx)
		}, func(err error) {
			certcancel()
		})

		// add TLS enabled server
		g.Add(func() error {
			return srv.ListenAndServeTLS("", "")
		}, func(err error) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = srv.Shutdown(ctx)
				cancel()
			}()
		})

	} else {
		// logging about command line
		logger.Info("setting up server")

		// set up server
		srv := newServer(config.String("listen"), handler, nil)

		// add non-TLS enabled server
		g.Add(func() error {
			return srv.ListenAndServe()
		}, func(err error) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = srv.Shutdown(ctx)
				cancel()
			}()
		})
	}

	// start run group
	if err := g.Run(); err != nil {
		logger.Error("error from run group", "error", err)
		os.Exit(1)
	}
}
