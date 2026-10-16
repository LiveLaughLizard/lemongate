package guardrails

import (
	"strings"
	"testing"
)

func TestEveryPresetBuilds(t *testing.T) {
	seen := map[string]bool{}
	packs := map[string]bool{}
	for _, p := range Packs {
		packs[p.ID] = true
	}
	for _, p := range Presets {
		if seen[p.ID] {
			t.Errorf("duplicate preset id %s", p.ID)
		}
		seen[p.ID] = true
		if !packs[p.Pack] {
			t.Errorf("%s: unknown pack %q", p.ID, p.Pack)
		}
		if !nameRe.MatchString(p.ID) {
			t.Errorf("%s: id is not a valid policy name", p.ID)
		}
		params := map[string]string{}
		for _, pr := range p.Params {
			params[pr.ID] = "some-model"
			if pr.Type == "list" {
				params[pr.ID] = "Acme Cloud, Globex AI"
			}
		}
		gs, err := p.BuildGuardrails(InstallOptions{Params: params})
		if err != nil {
			t.Errorf("%s: %v", p.ID, err)
			continue
		}
		for _, g := range gs {
			if _, err := compile(g); err != nil {
				t.Errorf("%s: compile %s: %v", p.ID, g.Name, err)
			}
			if g.Preset != p.ID || !strings.HasPrefix(g.Name, p.ID+"-") {
				t.Errorf("%s: guardrail %s not tagged with its preset", p.ID, g.Name)
			}
		}
		if p.RequiresModel() {
			if _, err := p.BuildGuardrails(InstallOptions{}); err == nil {
				t.Errorf("%s: expected an error when the model param is missing", p.ID)
			}
		}
	}
	if len(Presets) < 20 {
		t.Errorf("catalog unexpectedly small: %d", len(Presets))
	}
}

func TestPresetOverridesFallBackToBlock(t *testing.T) {
	p, _ := PresetByID("prompt-injection-heuristics")
	gs, err := p.BuildGuardrails(InstallOptions{Action: ActionMask, Mode: ModeBoth})
	if err != nil {
		t.Fatal(err)
	}
	if gs[0].Action != ActionBlock || gs[0].Mode != ModeBoth {
		t.Fatalf("got action=%s mode=%s", gs[0].Action, gs[0].Mode)
	}
}

func TestPresetBuildDoesNotMutateCatalog(t *testing.T) {
	p, _ := PresetByID("competitor-mentions")
	if _, err := p.BuildGuardrails(InstallOptions{Params: map[string]string{"competitors": "Acme"}}); err != nil {
		t.Fatal(err)
	}
	if len(p.Guardrails[0].Config.Words) != 0 {
		t.Fatal("catalog words were mutated")
	}
}
