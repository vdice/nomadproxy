package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var (
	hostname          = flag.String("hostname", "", "Tailscale hostname to serve on, used as the base name for MagicDNS or subdomain in your domain alias for HTTPS.")
	backendAddr       = flag.String("backend-addr", "", "Address of the Nomad server served over HTTPS, in scheme://host:port format. e.g http://localhost:4646.")
	backendCA         = flag.String("backend-ca", "", "CA File of the backend")
	backendClientCert = flag.String("backend-client-cert", "", "Client Cert File")
	backendClientKey  = flag.String("backend-client-key", "", "Client Key File")
	tailscaleDir      = flag.String("state-dir", "./", "Alternate directory to use for Tailscale state storage. If empty, a default is used.")
	useHTTPS          = flag.Bool("use-https", true, "Serve over HTTPS via your *.ts.net subdomain if enabled in Tailscale admin.")
)

func main() {
	var deviceTags []string
	flag.Func("device-tag", "Tag for the Tailscale device, eg 'tag:prod'. Can be specified multiple times.", func(s string) error {
		deviceTags = append(deviceTags, s)
		return nil
	})
	flag.Parse()
	if *hostname == "" || strings.Contains(*hostname, ".") {
		log.Fatal("missing or invalid --hostname")
	}
	if *backendAddr == "" {
		log.Fatal("missing --backend-addr")
	}

	ctx := context.Background()

	var authKey string
	var err error
	if authKey = os.Getenv("TS_AUTH_KEY"); authKey != "" {
		log.Println("using TS_AUTH_KEY for authenticate the device")
	} else {
		log.Println("using OAuth client to authenticate the device")
		oauthClient := newOauthClient()
		authKey, err = createAuthKey(ctx, oauthClient, deviceTags)
		if err != nil {
			log.Fatalf("couldn't get an auth key via OAuth client: %v", err)
		}
	}

	ts := &tsnet.Server{
		Dir:       *tailscaleDir,
		Hostname:  *hostname,
		Logf:      logger.Discard,
		AuthKey:   authKey,
		Ephemeral: true,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()
		return ts.Close()
	})
	g.Go(func() error {
		return nonClosedError(ts.Start())
	})

	g.Go(func() error {
		localClient, err := ts.LocalClient()
		if err != nil {
			return fmt.Errorf("error getting localclient: %v", err)
		}

		url, err := url.Parse(*backendAddr)
		if err != nil {
			return fmt.Errorf("couldn't parse backend address: %v", err)
		}

		proxy := httputil.NewSingleHostReverseProxy(url)
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			req.Host = req.URL.Host
			originalDirector(req)
		}
		proxy.ErrorLog = logger.StdLogger((logger.Discard))

		if backendCA != nil && *backendCA != "" {
			cert, err := os.ReadFile(*backendCA)
			if err != nil {
				return fmt.Errorf("could not open certificate file: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(cert)

			clientCert := *backendClientCert
			clientKey := *backendClientKey
			certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
			if err != nil {
				return fmt.Errorf("could not load certificate: %v", err)
			}
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      caCertPool,
					Certificates: []tls.Certificate{certificate},
				},
			}
		}

		var ln net.Listener
		if *useHTTPS {
			ln, err = ts.Listen("tcp", ":443")
			ln = tls.NewListener(ln, &tls.Config{
				GetCertificate: localClient.GetCertificate,
			})

			g.Go(func() error {
				// wait for tailscale to start before trying to fetch cert names
				for i := 0; i < 60; i++ {
					st, err := localClient.Status(ctx)
					if err != nil {
						log.Printf("error retrieving tailscale status; retrying: %v", err)
					} else {
						log.Printf("tailscale is %v", st.BackendState)
						if st.BackendState == "Running" {
							log.Println("tailscale is now running")
							break
						}
					}
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(time.Second):
					}
				}

				l80, err := ts.Listen("tcp", ":80")
				if err != nil {
					return err
				}
				name, ok := localClient.ExpandSNIName(ctx, *hostname)
				if !ok {
					return fmt.Errorf("can't get hostname for https redirect")
				}

				redirectServer := &http.Server{
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						http.Redirect(w, r, fmt.Sprintf("https://%s", name), http.StatusMovedPermanently)
					}),
				}

				go func() {
					<-ctx.Done()
					redirectServer.Shutdown(context.Background())
				}()

				return nonClosedError(redirectServer.Serve(l80))
			})
		} else {
			ln, err = ts.Listen("tcp", ":80")
		}
		if err != nil {
			return err
		}

		server := &http.Server{
			Handler:     auditRequests(ctx, localClient, proxy),
			BaseContext: func(net.Listener) context.Context { return ctx },
		}

		go func() {
			<-ctx.Done()
			server.Shutdown(context.Background())
		}()

		log.Printf("nomadproxy running at %v, proxying to %v", ln.Addr(), *backendAddr)
		return nonClosedError(server.Serve(ln))
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("Execution failed: %v", err)
	}
}

func newOauthClient() *tailscale.Client {
	tailnet := os.Getenv("TAILNET_NAME")
	clientID := os.Getenv("TS_OAUTH_CLIENT_ID")
	clientSecret := os.Getenv("TS_OAUTH_CLIENT_SECRET")

	if tailnet == "" || clientID == "" || clientSecret == "" {
		log.Fatal("missing OAuth client configuration (TAILNET_NAME, TS_OAUTH_CLIENT_ID, TS_OAUTH_CLIENT_SECRET)")
	}

	return &tailscale.Client{
		Tailnet: tailnet,
		HTTP: tailscale.OAuthConfig{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"auth_keys:write"},
		}.HTTPClient(),
	}
}

func createAuthKey(ctx context.Context, client *tailscale.Client, tags []string) (string, error) {
	capabilities := tailscale.KeyCapabilities{}
	capabilities.Devices.Create.Ephemeral = true
	capabilities.Devices.Create.Reusable = false
	capabilities.Devices.Create.Preauthorized = false
	capabilities.Devices.Create.Tags = tags

	req := tailscale.CreateKeyRequest{
		Capabilities:  capabilities,
		ExpirySeconds: 60,
	}

	keyMeta, err := client.Keys().Create(ctx, req)
	if err != nil {
		return "", err
	}

	return keyMeta.Key, nil
}

func auditRequests(ctx context.Context, client *local.Client, next http.Handler) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		err := auditRequest(ctx, client, req)
		if err != nil {
			resp.WriteHeader(500)
			resp.Write([]byte("request audit failed"))
			return
		}

		next.ServeHTTP(resp, req)
	}
}

func auditRequest(ctx context.Context, client *local.Client, req *http.Request) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	whois, err := client.WhoIs(ctx, req.RemoteAddr)
	if err != nil {
		return fmt.Errorf("getting client identity: %v", err)
	}

	user, machine := "", ""
	if whois.Node != nil {
		if whois.Node.Hostinfo.ShareeNode() {
			machine = "external-device"
		} else {
			machine = strings.TrimSuffix(whois.Node.Name, ".")
		}
	}
	if whois.UserProfile != nil {
		user = whois.UserProfile.LoginName
		if user == "tagged-devices" && whois.Node != nil {
			user = strings.Join(whois.Node.Tags, ",")
		}
	}
	if user == "" || machine == "" {
		return fmt.Errorf("couldn't identify source user and machine (user %q, machine %q)", user, machine)
	}
	log.Printf("%s %s from (machine %s, user %s)", req.Method, req.URL.Path, machine, user)
	return nil
}

func nonClosedError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
