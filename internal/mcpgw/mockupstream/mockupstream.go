// Package mockupstream is a tiny MCP server used for local development and tests.
// It exposes a handful of deterministic tools over Streamable HTTP (/mcp) and
// the legacy SSE transport (/sse).
package mockupstream

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options configure the mock server.
type Options struct {
	// Name is reported as the server implementation name (default "mock-mcp").
	Name string
	// Token, when set, is required as "Authorization: Bearer <token>".
	Token string
}

// Server is a running mock MCP upstream.
type Server struct {
	opts  Options
	mcp   *mcp.Server
	Calls atomic.Int64 // tool invocations served
}

var lemonFacts = []string{
	"Lemons float because their peel is less dense than water.",
	"A single lemon tree can produce up to 270 kg of fruit a year.",
	"Lemon juice is about 5-6% citric acid, giving it a pH near 2.",
	"Lemons are a hybrid of bitter orange and citron.",
	"The Spanish city of Murcia is one of Europe's largest lemon producers.",
	"Lemon peel contains more vitamin C than the juice by weight.",
	"Lemons were once so rare that kings gave them as gifts.",
}

type factsIn struct {
	Count int    `json:"count,omitempty" jsonschema:"How many facts to return (1-5, default 1)"`
	Topic string `json:"topic,omitempty" jsonschema:"Optional keyword the facts should mention"`
}

type addIn struct {
	A float64 `json:"a" jsonschema:"First addend"`
	B float64 `json:"b" jsonschema:"Second addend"`
}

type addOut struct {
	Sum float64 `json:"sum" jsonschema:"a + b"`
}

type echoIn struct {
	Message   string `json:"message" jsonschema:"Text to echo back"`
	Uppercase bool   `json:"uppercase,omitempty" jsonschema:"Shout the message"`
	Repeat    int    `json:"repeat,omitempty" jsonschema:"Number of repetitions (default 1, max 10)"`
}

type failIn struct {
	Reason string `json:"reason,omitempty" jsonschema:"Error message to return"`
}

// New builds the mock server.
func New(opts Options) *Server {
	if opts.Name == "" {
		opts.Name = "mock-mcp"
	}
	s := &Server{opts: opts}
	srv := mcp.NewServer(&mcp.Implementation{Name: opts.Name, Title: "LemonGate mock MCP server", Version: "1.0.0"},
		&mcp.ServerOptions{Instructions: "Deterministic tools for testing the LemonGate MCP gateway."})

	mcp.AddTool(srv, &mcp.Tool{Name: "lemon_facts", Title: "Lemon facts", Description: "Returns one or more facts about lemons."},
		func(ctx context.Context, req *mcp.CallToolRequest, in factsIn) (*mcp.CallToolResult, any, error) {
			s.Calls.Add(1)
			n := min(max(in.Count, 1), 5)
			var out []string
			for _, f := range lemonFacts {
				if in.Topic == "" || strings.Contains(strings.ToLower(f), strings.ToLower(in.Topic)) {
					out = append(out, f)
				}
				if len(out) == n {
					break
				}
			}
			if len(out) == 0 {
				out = []string{fmt.Sprintf("No lemon facts mention %q, but lemons are still great.", in.Topic)}
			}
			content := make([]mcp.Content, 0, len(out))
			for _, f := range out {
				content = append(content, &mcp.TextContent{Text: f})
			}
			return &mcp.CallToolResult{Content: content}, nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "add_numbers", Title: "Add numbers", Description: "Adds two numbers and returns the sum."},
		func(ctx context.Context, req *mcp.CallToolRequest, in addIn) (*mcp.CallToolResult, addOut, error) {
			s.Calls.Add(1)
			sum := in.A + in.B
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%g + %g = %g", in.A, in.B, sum)}}}, addOut{Sum: sum}, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "Echoes a message, optionally upper-cased and repeated."},
		func(ctx context.Context, req *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			s.Calls.Add(1)
			msg := in.Message
			if in.Uppercase {
				msg = strings.ToUpper(msg)
			}
			n := min(max(in.Repeat, 1), 10)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.TrimSpace(strings.Repeat(msg+" ", n))}}}, nil, nil
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "always_fail", Description: "Always returns a tool error (useful for testing error handling)."},
		func(ctx context.Context, req *mcp.CallToolRequest, in failIn) (*mcp.CallToolResult, any, error) {
			s.Calls.Add(1)
			reason := in.Reason
			if reason == "" {
				reason = "this tool always fails"
			}
			return nil, nil, errors.New(reason)
		})

	s.mcp = srv
	return s
}

// MCP returns the underlying SDK server (e.g. to add tools in tests).
func (s *Server) MCP() *mcp.Server { return s.mcp }

// Handler serves Streamable HTTP on /mcp (and /) and SSE on /sse.
func (s *Server) Handler() http.Handler {
	getServer := func(*http.Request) *mcp.Server { return s.mcp }
	streamable := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	sse := mcp.NewSSEHandler(getServer, nil)
	mux := http.NewServeMux()
	mux.Handle("/sse", sse)
	mux.Handle("/sse/", sse)
	mux.Handle("/mcp", streamable)
	mux.Handle("/", streamable)
	return s.auth(mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	if s.opts.Token == "" {
		return next
	}
	want := []byte("Bearer " + s.opts.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
