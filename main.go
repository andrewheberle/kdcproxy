package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/andrewheberle/go-kdcproxy/kdcproxy"
	"github.com/cloudflare/certinel/fswatcher"
	"github.com/justinas/alice"
	"github.com/oklog/run"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func main() {
	// command line flags
	pflag.Bool("debug", false, "Enable debug logging")
	pflag.String("listen", "127.0.0.1:8080", "Listen address")
	pflag.String("keytab", "", "Kerberos keytab")
	pflag.String("krb5conf", "", "Kerberos config file")
	pflag.String("cert", "", "TLS certificate")
	pflag.String("key", "", "TLS key")
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

	// logging about command line
	log.Info().
		Str("krb5conf", viper.GetString("krb5conf")).
		Str("listen", viper.GetString("listen")).
		Str("cert", viper.GetString("cert")).
		Str("key", viper.GetString("key")).
		Bool("debug", viper.GetBool("debug")).
		Msg("configuration options")

	// set up middelware chain for logging
	c := alice.New()
	c = c.Append(hlog.NewHandler(logger))
	c = c.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Interface("headers", r.Header).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))
	c = c.Append(hlog.RemoteAddrHandler("ip"))
	c = c.Append(hlog.UserAgentHandler("user_agent"))
	c = c.Append(hlog.RefererHandler("referer"))
	c = c.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	// load keytab
	/*keytab, err := keytab.Load(viper.GetString("krb5conf"))
	if err != nil {
		log.Fatal().Err(err).Msg("could not load keytab")
	}*/

	// set up kdc proxy
	k, err := kdcproxy.InitKdcProxy(viper.GetString("krb5conf"))
	if err != nil {
		log.Fatal().Err(err).Msg("could not load kerberos config")
	}

	// add to http service
	http.Handle("/KdcProxy", c.ThenFunc(k.Handler))

	// set up server
	srv := http.Server{
		Addr:         viper.GetString("listen"),
		ReadTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
	}

	// run group
	g := run.Group{}

	// start server
	if viper.GetString("cert") != "" && viper.GetString("key") != "" {
		certctx, certcancel := context.WithCancel(context.Background())

		certinel, err := fswatcher.New(viper.GetString("cert"), viper.GetString("key"))
		if err != nil {
			log.Fatal().Err(err).Msg("unable to read server certificate")
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
		log.Fatal().Err(err).Send()
	}
}
