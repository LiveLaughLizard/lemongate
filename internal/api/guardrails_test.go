package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"lemongate/internal/guardrails"
)

func TestGuardrailPolicyAPI(t *testing.T) {
	srv, d := newTestServer(t)
	ctx := context.Background()
	eng := guardrails.New(d.Store.Pool, d.Settings, nil, d.Registry)
	SetHooks(Hooks{Guardrails: eng, ReloadGuardrails: eng.Reload})
	t.Cleanup(func() { SetHooks(Hooks{}) })
	sfx := fmt.Sprint(time.Now().UnixNano())
	master := client{t, srv.URL, testMaster}

	cat := master.must("GET", "/api/v1/guardrail-catalog", nil, 200)
	if len(cat["families"].([]any)) != len(guardrails.Families) || len(cat["entities"].([]any)) == 0 {
		t.Fatalf("catalog: %v", cat["families"])
	}

	g := master.must("POST", "/api/v1/guardrails", map[string]any{"name": "pol-g-" + sfx, "kind": "pii", "mode": "pre", "action": "mask",
		"config": map[string]any{"entities": []string{"email"}}, "enabled": true}, 201)
	gid := g["id"].(string)
	t.Cleanup(func() { _ = eng.Delete(ctx, gid) })

	name := "pol-" + sfx
	master.must("POST", "/api/v1/guardrail-policies", map[string]any{"name": name, "guardrails": []string{"missing-" + sfx}}, 400)
	p := master.must("POST", "/api/v1/guardrail-policies", map[string]any{"name": name, "guardrails": []string{"pol-g-" + sfx}}, 201)
	pid := p["id"].(string)
	if p["enabled"] != true || p["default_on"] != false {
		t.Fatalf("defaults: %v", p)
	}
	master.must("POST", "/api/v1/guardrail-policies", map[string]any{"name": name, "guardrails": []string{"pol-g-" + sfx}}, 409)

	k := master.must("POST", "/api/v1/keys", map[string]any{"alias": "pol-key-" + sfx, "policies": []string{name}}, 201)
	kid := k["id"].(string)
	t.Cleanup(func() { _ = d.Store.PurgeKey(ctx, kid) })

	got := master.must("GET", "/api/v1/guardrail-policies/"+name, nil, 200)
	if got["key_count"].(float64) != 1 {
		t.Fatalf("key_count: %v", got)
	}
	up := master.must("PATCH", "/api/v1/guardrail-policies/"+pid, map[string]any{"description": "updated"}, 200)
	if up["description"] != "updated" || up["name"] != name {
		t.Fatalf("patch: %v", up)
	}
	master.must("DELETE", "/api/v1/guardrail-policies/"+pid+"?with_guardrails=true", nil, 200)
	master.must("GET", "/api/v1/guardrail-policies/"+pid, nil, 404)
	if _, err := eng.Get(ctx, gid); err == nil {
		t.Fatal("guardrail used only by the deleted policy should be gone")
	}
	key := master.must("GET", "/api/v1/keys/"+kid, nil, 200)
	if pols, _ := key["policies"].([]any); len(pols) != 0 {
		t.Fatalf("key still references the deleted policy: %v", pols)
	}

	// Presets: catalog, install with a missing required param, install, uninstall.
	list := master.must("GET", "/api/v1/guardrail-presets", nil, 200)
	if int(list["count"].(float64)) != len(guardrails.Presets) || list["packs"] == nil {
		t.Fatalf("presets: %v", list["count"])
	}
	const preset = "competitor-mentions"
	master.must("POST", "/api/v1/guardrail-presets/"+preset+"/install", map[string]any{}, 400)
	master.must("POST", "/api/v1/guardrail-presets/nope/install", map[string]any{}, 404)
	inst := master.must("POST", "/api/v1/guardrail-presets/"+preset+"/install", map[string]any{"params": map[string]string{"competitors": "Acme, Globex"}, "action": "log"}, 200)
	t.Cleanup(func() {
		if pol, err := eng.GetPolicy(ctx, preset); err == nil {
			_ = eng.DeletePolicy(ctx, pol.ID, true)
		}
	})
	if inst["preset"] != preset || inst["name"] != preset {
		t.Fatalf("install: %v", inst)
	}
	gr, err := eng.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range gr {
		if x.Preset == preset && (x.Action != "log" || len(x.Config.Words) != 2) {
			t.Fatalf("installed guardrail: %+v", x)
		}
	}
	master.must("DELETE", "/api/v1/guardrail-presets/"+preset, nil, 200)
	master.must("DELETE", "/api/v1/guardrail-presets/"+preset, nil, 404)
}
