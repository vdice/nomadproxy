package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var (
	hostname          = flag.String("hostname", "", "Tailscale hostname to serve on, used as the base name for MagicDNS or subdomain in your domain alias for HTTPS.")
	backendAddr       = flag.String("backend-addr", "", "Address of the Nomad server served over HTTPS, in scheme://host:port format. e.g http://localhost:4646.")
	backendCA         = flag.String("backend-ca", "", "CA File of the backend")
	backendClientCert = flag.String("backend-client-cert", "", "Client Cert File")
	backendClientKey  = flag.String("backend-client-key", "", "Cleint Key File")
	tailscaleDir      = flag.String("state-dir", "./", "Alternate directory to use for Tailscale state storage. If empty, a default is used.")
	useHTTPS          = flag.Bool("use-https", true, "Serve over HTTPS via your *.ts.net subdomain if enabled in Tailscale admin.")
)

func main() {
	flag.Parse()
	if *hostname == "" || strings.Contains(*hostname, ".") {
		log.Fatal("missing or invalid --hostname")
	}
	if *backendAddr == "" {
		log.Fatal("missing --backend-addr")
	}
	ts := &tsnet.Server{
		Dir:      *tailscaleDir,
		Hostname: *hostname,
		Logf:     logger.Discard,
	}

	if err := ts.Start(); err != nil {
		log.Fatalf("Error starting tsnet.Server: %v", err)
	}
	localClient, err := ts.LocalClient()
	if err != nil {
		log.Fatalf("Error getting localclient: %v", err)
	}

	url, err := url.Parse(*backendAddr)
	if err != nil {
		log.Fatalf("couldn't parse backend address: %v", err)
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
			log.Fatalf("could not open certificate file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)

		clientCert := *backendClientCert
		clientKey := *backendClientKey
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Fatalf("could not load certificate: %v", err)
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

		go func() {
			// wait for tailscale to start before trying to fetch cert names
			for i := 0; i < 60; i++ {
				st, err := localClient.Status(context.Background())
				if err != nil {
					log.Printf("error retrieving tailscale status; retrying: %v", err)
				} else {
					log.Printf("tailscale is %v", st.BackendState)
					if st.BackendState == "Running" {
						log.Println("tailscale is now runnning")
						break
					}
				}
				time.Sleep(time.Second)
			}

			l80, err := ts.Listen("tcp", ":80")
			if err != nil {
				log.Fatal(err)
			}
			name, ok := localClient.ExpandSNIName(context.Background(), *hostname)
			if !ok {
				log.Fatalf("can't get hostname for https redirect")
			}
			if err := http.Serve(l80, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, fmt.Sprintf("https://%s", name), http.StatusMovedPermanently)
			})); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		ln, err = ts.Listen("tcp", ":80")
	}
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("nomadproxy running at %v, proxying to %v", ln.Addr(), *backendAddr)
	log.Fatal(http.Serve(ln, auditRequests(localClient, proxy)))
}

func auditRequests(client *tailscale.LocalClient, next http.Handler) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		err := auditRequest(client, req)
		if err != nil {
			resp.WriteHeader(500)
			resp.Write([]byte("request audit failed"))
			return
		}

		next.ServeHTTP(resp, req)
	}
}

func auditRequest(client *tailscale.LocalClient, req *http.Request) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
