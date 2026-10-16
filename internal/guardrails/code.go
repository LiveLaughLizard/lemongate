package guardrails

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Language is a programming language the code_execution kind can detect.
type Language struct {
	ID    string
	Label string
}

// Code languages (Config.Languages).
const (
	LangShell      = "shell"
	LangPython     = "python"
	LangJavaScript = "javascript"
	LangSQL        = "sql"
	LangPowerShell = "powershell"
)

// CodeLanguages lists the languages code_execution can detect, in display order.
var CodeLanguages = []Language{
	{ID: LangShell, Label: "Shell (sh, bash, zsh)"},
	{ID: LangPython, Label: "Python"},
	{ID: LangJavaScript, Label: "JavaScript / TypeScript"},
	{ID: LangSQL, Label: "SQL"},
	{ID: LangPowerShell, Label: "PowerShell"},
}

func init() {
	registerKind(KindCodeExecution, kindImpl{validate: validateCode, compile: compileCode, check: checkCode})
}

func codeLanguageIDs() []string {
	out := make([]string, len(CodeLanguages))
	for i, l := range CodeLanguages {
		out[i] = l.ID
	}
	return out
}

func validateCode(c *Config) error {
	c.Languages = cleanList(c.Languages)
	for i, l := range c.Languages {
		l = strings.ToLower(l)
		c.Languages[i] = l
		if !contains(codeLanguageIDs(), l) {
			return fmt.Errorf("unknown code language %q", l)
		}
	}
	return nil
}

func compileCode(r *rule) error {
	langs := r.g.Config.Languages
	if len(langs) == 0 {
		langs = codeLanguageIDs()
	}
	set := map[string]bool{}
	for _, l := range langs {
		set[strings.ToLower(l)] = true
	}
	r.ext = set
	return nil
}

func checkCode(_ context.Context, _ *Engine, r *rule, in checkInput) finding {
	set, _ := r.ext.(map[string]bool)
	text := joinSegments(in.segs)
	langs, patterns := DetectCode(text, set)
	if len(langs) == 0 && len(patterns) == 0 {
		return finding{}
	}
	var parts []string
	if len(langs) > 0 {
		parts = append(parts, "languages: "+strings.Join(langs, ", "))
	}
	if len(patterns) > 0 {
		parts = append(parts, "patterns: "+strings.Join(patterns, ", "))
	}
	reason := "contains executable code"
	if len(patterns) > 0 {
		reason = "contains destructive or dangerous code (" + strings.Join(patterns, ", ") + ")"
	}
	return finding{hit: true, detail: strings.Join(parts, "; "), reason: reason}
}

// fenceAliases maps code-fence info strings to a language id.
var fenceAliases = map[string]string{
	"sh": LangShell, "bash": LangShell, "zsh": LangShell, "shell": LangShell, "console": LangShell, "shellscript": LangShell,
	"ksh": LangShell, "fish": LangShell, "shell-session": LangShell, "shellsession": LangShell, "terminal": LangShell,
	"py": LangPython, "python": LangPython, "python3": LangPython, "py3": LangPython, "pycon": LangPython, "ipython": LangPython,
	"js": LangJavaScript, "javascript": LangJavaScript, "node": LangJavaScript, "nodejs": LangJavaScript, "mjs": LangJavaScript,
	"cjs": LangJavaScript, "jsx": LangJavaScript, "ts": LangJavaScript, "typescript": LangJavaScript, "tsx": LangJavaScript,
	"sql": LangSQL, "mysql": LangSQL, "postgresql": LangSQL, "postgres": LangSQL, "psql": LangSQL, "plsql": LangSQL,
	"pgsql": LangSQL, "tsql": LangSQL, "t-sql": LangSQL, "sqlite": LangSQL, "mssql": LangSQL,
	"powershell": LangPowerShell, "ps1": LangPowerShell, "pwsh": LangPowerShell, "ps": LangPowerShell, "posh": LangPowerShell,
}

var fenceRe = regexp.MustCompile("(?m)^[ \t]{0,3}(?:```+|~~~+)[ \t]*([A-Za-z0-9_+.#-]+)")

// codePattern is one destructive or dangerous construct.
type codePattern struct {
	name  string
	langs []string
	re    *regexp.Regexp
	// match, when set, replaces re (for checks a regexp cannot express).
	match func(string) bool
}

var codePatterns = func() []codePattern {
	re := regexp.MustCompile
	sh, py, js, sql, ps := []string{LangShell}, []string{LangPython}, []string{LangJavaScript}, []string{LangSQL}, []string{LangPowerShell}
	return []codePattern{
		// --- shell ---
		{name: "rm_rf_root", langs: sh, re: re(`(?i)\brm\s+(?:-[a-z]*(?:r[a-z]*f|f[a-z]*r)[a-z]*|(?:-r|-R|--recursive)\s+(?:-f|--force)|(?:-f|--force)\s+(?:-r|-R|--recursive))\s+(?:--no-preserve-root\s+)?(?:/(?:\*|\s|$|;|&|\|)|~/?(?:\*|\s|$|;)|\*|\$home\b|\$\{?home\}?|/(?:etc|usr|var|home|boot|bin|sbin|lib|lib64|root|opt|sys|dev|proc)\b)|--no-preserve-root`)},
		{name: "curl_pipe_shell", langs: sh, re: re(`(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da|fi)?sh\b|\b(?:ba|z)?sh\s+(?:-c\s+)?["']?\$\(\s*(?:curl|wget)\b|\b(?:ba|z)?sh\s+<\(\s*(?:curl|wget)\b`)},
		{name: "chmod_777", langs: sh, re: re(`(?i)\bchmod\s+(?:-[rRf]+\s+)*(?:0?777|a\+rwx|ugo\+rwx)\b`)},
		{name: "mkfs", langs: sh, re: re(`\bmkfs(?:\.[a-z0-9]+)?\s+\S`)},
		{name: "dd_disk_write", langs: sh, re: re(`\bdd\s+(?:[a-z]+=\S+\s+)*if=\S+`)},
		{name: "disk_overwrite", langs: sh, re: re(`>\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|mmcblk\d|disk\d)`)},
		{name: "fork_bomb", langs: sh, re: re(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\b(\w+)\s*\(\s*\)\s*\{\s*(\w+)\s*\|\s*(\w+)\s*&\s*\}\s*;\s*\w+`)},
		{name: "reverse_shell", langs: sh, re: re(`(?i)/dev/(?:tcp|udp)/[\w.\-]+/\d+|\bn(?:c|cat|etcat)\b[^\n]*\s-[a-z]*e\s+/bin/(?:ba)?sh|\bsocat\b[^\n]*\bexec:|\bmkfifo\b[^\n]*\bn(?:c|cat)\b`)},
		// --- python ---
		{name: "os_system", langs: py, re: re(`\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(`)},
		{name: "subprocess", langs: py, re: re(`\bsubprocess\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(`)},
		{name: "dynamic_import_os", langs: py, re: re(`__import__\s*\(\s*['"](?:os|subprocess|pty)['"]`)},
		{name: "pty_spawn", langs: py, re: re(`\bpty\.spawn\s*\(`)},
		{name: "rmtree", langs: py, re: re(`\bshutil\.rmtree\s*\(\s*['"](?:/|~|C:\\)`)},
		{name: "eval_exec", langs: []string{LangPython, LangJavaScript}, re: re(`(?:^|[^.\w$])(?:eval|exec)\(\s*(?:[\w"'\x60(]|$)`)},
		// --- javascript ---
		{name: "child_process", langs: js, re: re(`\bchild_process\b|\b(?:execSync|spawnSync|execFileSync)\s*\(`)},
		{name: "new_function", langs: js, re: re(`\bnew\s+Function\s*\(\s*['"\x60]`)},
		{name: "fs_rm_recursive", langs: js, re: re(`\bfs(?:\.promises)?\.(?:rm|rmdir)(?:Sync)?\s*\([^)]*recursive\s*:\s*true`)},
		// --- sql ---
		{name: "drop_table", langs: sql, re: re(`(?i)\bdrop\s+(?:table|database|schema|view|index|user)\s+(?:if\s+exists\s+)?[\w."\x60\[\]]+`)},
		{name: "truncate_table", langs: sql, re: re(`(?i)\btruncate\s+table\s+[\w."\x60\[\]]+`)},
		{name: "delete_without_where", langs: sql, match: deleteWithoutWhere},
		{name: "update_without_where", langs: sql, match: updateWithoutWhere},
		{name: "xp_cmdshell", langs: sql, re: re(`(?i)\bxp_cmdshell\b`)},
		{name: "sql_file_write", langs: sql, re: re(`(?i)\binto\s+(?:out|dump)file\s+['"]|\bcopy\s+\S+\s+(?:from|to)\s+program\b`)},
		// --- powershell ---
		{name: "invoke_expression", langs: ps, re: re(`(?i)\binvoke-expression\b|\|\s*iex\b|(?:^|[\s;(])iex\s*[\(\$'"]`)},
		{name: "encoded_command", langs: ps, re: re(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{8,}`)},
		{name: "execution_policy_bypass", langs: ps, re: re(`(?i)\bset-executionpolicy\s+(?:-executionpolicy\s+)?(?:bypass|unrestricted)\b|-(?:executionpolicy|exec|ep)\s+(?:bypass|unrestricted)\b`)},
		{name: "download_cradle", langs: ps, re: re(`(?i)\.downloadstring\s*\(|\bnew-object\s+(?:system\.)?net\.webclient\b`)},
		{name: "recursive_delete_system", langs: ps, re: re(`(?i)\bremove-item\b[^\n]*-recurse\b[^\n]*(?:\bc:\\(?:\s|$|\*|windows)|\$env:(?:systemroot|windir))|\bformat-volume\b|\bformat\s+c:`)},
	}
}()

var (
	deleteFromRe = regexp.MustCompile(`(?i)\bdelete\s+from\s+[\w."\x60\[\]]+`)
	updateSetRe  = regexp.MustCompile(`(?i)\bupdate\s+[\w."\x60\[\]]+\s+set\s+`)
	whereRe      = regexp.MustCompile(`(?i)\bwhere\b`)
	aliasOnlyRe  = regexp.MustCompile(`(?i)^\s*(?:(?:as\s+)?\w+\s*)?$`)
)

// statementRest returns the text after a match up to the next ';' (or a blank
// line / the end) and whether a ';' terminated it.
func statementRest(text string, end int) (string, bool) {
	rest := text[end:]
	if i := strings.Index(rest, "\n\n"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ';'); i >= 0 {
		return rest[:i], true
	}
	return rest, false
}

// deleteWithoutWhere finds "DELETE FROM t;" (or at the end of the text) with no WHERE.
// Prose such as "delete from your inbox any spam" is ignored.
func deleteWithoutWhere(text string) bool {
	for _, loc := range deleteFromRe.FindAllStringIndex(text, -1) {
		rest, terminated := statementRest(text, loc[1])
		if whereRe.MatchString(rest) {
			continue
		}
		if strings.TrimSpace(rest) == "" || (terminated && aliasOnlyRe.MatchString(rest)) {
			return true
		}
	}
	return false
}

// updateWithoutWhere finds "UPDATE t SET c = v" with no WHERE before the statement ends.
func updateWithoutWhere(text string) bool {
	for _, loc := range updateSetRe.FindAllStringIndex(text, -1) {
		rest, _ := statementRest(text, loc[1])
		if !strings.Contains(rest, "=") || whereRe.MatchString(rest) {
			continue
		}
		// The assignment list must look like SQL: col = value[, col = value].
		if sqlAssignRe.MatchString(rest) {
			return true
		}
	}
	return false
}

var sqlAssignRe = regexp.MustCompile(`^\s*[\w."\x60\[\]]+\s*=\s*\S`)

// DetectCode reports the fenced code languages and destructive patterns found
// in text, restricted to the given language set (all languages when nil).
func DetectCode(text string, langs map[string]bool) (languages, patterns []string) {
	want := func(l string) bool { return langs == nil || langs[l] }
	seen := map[string]bool{}
	for _, m := range fenceRe.FindAllStringSubmatch(text, -1) {
		l := fenceAliases[strings.ToLower(m[1])]
		if l != "" && want(l) && !seen[l] {
			seen[l] = true
			languages = append(languages, l)
		}
	}
	for _, p := range codePatterns {
		ok := false
		for _, l := range p.langs {
			if want(l) {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		var hit bool
		if p.match != nil {
			hit = p.match(text)
		} else {
			hit = p.re.MatchString(text)
		}
		if hit {
			patterns = append(patterns, p.name)
			for _, l := range p.langs {
				if want(l) && !seen[l] {
					seen[l] = true
					languages = append(languages, l)
				}
			}
		}
	}
	return languages, patterns
}
