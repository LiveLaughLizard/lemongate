// mockmcp is a tiny upstream MCP server for local development and tests.
//
//	go run ./cmd/mockmcp -addr :8101 [-token secret] [-name mock-mcp]
//
// Streamable HTTP is served at /mcp, the legacy SSE transport at /sse.
// Tools: lemon_facts, add_numbers, echo, always_fail.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"lemongate/internal/mcpgw/mockupstream"
)

func main() {
	addr := flag.String("addr", ":8101", "listen address")
	token := flag.String("token", "", "require this bearer token")
	name := flag.String("name", "mock-mcp", "server implementation name")
	flag.Parse()

	s := mockupstream.New(mockupstream.Options{Name: *name, Token: *token})
	srv := &http.Server{Addr: *addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("mockmcp %q listening on %s (streamable: /mcp, sse: /sse, auth: %v)", *name, *addr, *token != "")
	log.Fatal(srv.ListenAndServe())
}
