package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/andrewheberle/kdcproxy"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/justinas/alice"
	"github.com/oklog/run"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	"github.com/rs/zerolog/hlog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	// command line flags
	pflag.Bool("debug", false, "Enable debug logging")
	pflag.String("listen", "127.0.0.1:8080", "Service listen address")
	pflag.String("cert", "", "TLS certificate")
	pflag.String("key", "", "TLS key")
	pflag.String("krb5conf", "", "Path to krb5.conf")
	pflag.Parse()

	// viper setup
	viper.SetEnvPrefix("kdc_proxy")
	viper.AutomaticEnv()
	viper.BindPFlags(pflag.CommandLine)

	// logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if viper.GetBool("debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	logwriter := diode.NewWriter(os.Stdout, 1000, 0, func(missed int) {
		fmt.Printf("Dropped %d messages\n", missed)
	})
	logger := zerolog.New(logwriter).With().Timestamp().Logger()

	// set up middelware chain for logging
	c := alice.New()
	c = c.Append(hlog.NewHandler(logger))
	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Send()
	}))
	c = c.Append(hlog.RemoteAddrHandler("ip"))
	c = c.Append(hlog.UserAgentHandler("user_agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	// set up kdc proxy
	k, err := kdcproxy.InitKdcProxyWithConfig(logger, viper.GetString("krb5conf"))
	if err != nil {
		logger.Fatal().Err(err).Msg("could not set up kdc proxy")
	}

	// add to http service
	http.Handle("/KdcProxy", c.ThenFunc(k.Handler))

	// set up server
	srv := http.Server{
		Addr:         viper.GetString("listen"),
		ReadTimeout:  time.Second * 30,
		WriteTimeout: time.Second * 30,
	}

	// run group
	g := run.Group{}

	// start server
	if viper.GetString("cert") != "" && viper.GetString("key") != "" {
		// logging about command line
		logger.Info().
			Bool("debug", viper.GetBool("debug")).
			Str("cert", viper.GetString("cert")).
			Str("key", viper.GetString("key")).
			Msg("setting up tls server")

		certctx, certcancel := context.WithCancel(context.Background())

		certinel, err := fswatcher.New(viper.GetString("cert"), viper.GetString("key"))
		if err != nil {
			logger.Fatal().Err(err).Msg("unable to read server certificate")
		}

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
				srv.Shutdown(ctx)
				cancel()
			}()
		})

	} else {
		// logging about command line
		logger.Info().
			Bool("debug", viper.GetBool("debug")).
			Msg("setting up server")

		// add non-TLS enabled server
		g.Add(func() error {
			return srv.ListenAndServe()
		}, func(err error) {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				srv.Shutdown(ctx)
				cancel()
			}()
		})
	}

	// start run group
	if err := g.Run(); err != nil {
		logger.Fatal().Err(err).Send()
	}
}