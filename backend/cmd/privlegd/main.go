// Command privlegd is the privleg service daemon: the management plane for the holistic
// rights standard. It validates the shared holistic session, reads each service's declared
// rights from /etc/holistic/permissions.d, lists holistic-managed users, and toggles a
// user's rights or admin status via the narrow privleg-grant / privleg-set-admin wrappers.
// It runs unprivileged and escalates only through those two wrappers.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"privleg/internal/api"
	"privleg/internal/auth"
	"privleg/internal/catalog"
	"privleg/internal/invites"
	"privleg/internal/rights"
	"privleg/internal/users"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8772", "address to listen on")
	permsDir := flag.String("perms-dir", catalog.DefaultDir, "rights manifest drop-in directory")
	flag.Parse()

	secret, err := auth.LoadSecret()
	if err != nil {
		log.Fatalf("privlegd: %v", err)
	}
	adminGroup := os.Getenv("PRIVLEG_ADMIN_GROUP") // defaults to "sudo" in NewVerifier
	v := auth.NewVerifier(secret, adminGroup)
	cat := catalog.New(*permsDir)
	ul := users.NewLister(os.Getenv("PRIVLEG_USERS_GROUP"), adminGroup)

	// The rights config layer (groups + per-user assignments/overrides) is privleg-private
	// state; the materializer resolves it and syncs it down to live Linux groups.
	rpath := os.Getenv("PRIVLEG_RIGHTS")
	if rpath == "" {
		rpath = rights.DefaultPath
	}
	rstore, err := rights.Open(rpath)
	if err != nil {
		log.Fatalf("privlegd: open rights store %s: %v", rpath, err)
	}
	mat := rights.NewMaterializer(rstore, cat, ul)

	srv := &http.Server{
		Handler:           api.New(v, cat, ul, rstore, mat).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Bind synchronously so an "address in use" surfaces here, not in a goroutine.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("privlegd: listen %s: %v", *listen, err)
	}
	go func() {
		log.Printf("privlegd listening on %s (rights from %s)", *listen, *permsDir)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("privlegd: %v", err)
		}
	}()

	// Apply pending invite rights configs in the background. The registration flow lives in the
	// dashboard, so privleg learns of a new account by watching the shared invite store: when an
	// invite that carried a config is consumed, its config becomes the new user's config and is
	// materialized. Runs once at startup, then on a short interval.
	go func() {
		reconcile := func() {
			if err := mat.ReconcileInvites(invites.UsedBy); err != nil {
				log.Printf("privlegd: reconcile invites: %v", err)
			}
		}
		reconcile()
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for range t.C {
			reconcile()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	log.Print("privlegd stopped")
}
