package guardrails

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultInjectionThreshold is used when a prompt_injection guardrail has no threshold.
const DefaultInjectionThreshold = 0.5

func init() {
	registerKind(KindPromptInjection, kindImpl{validate: validateInjection, check: checkInjection})
}

func validateInjection(c *Config) error {
	if c.Threshold < 0 || c.Threshold > 1 {
		return errors.New("threshold must be between 0 and 1")
	}
	if c.Threshold == 0 {
		c.Threshold = DefaultInjectionThreshold
	}
	return nil
}

func checkInjection(_ context.Context, _ *Engine, r *rule, in checkInput) finding {
	text := joinSegments(in.segs)
	if strings.TrimSpace(text) == "" {
		return finding{}
	}
	th := r.g.Config.Threshold
	if th <= 0 {
		th = DefaultInjectionThreshold
	}
	score, signals := InjectionScore(text)
	if len(signals) == 0 {
		return finding{}
	}
	detail := fmt.Sprintf("signals: %s; score %.2f", strings.Join(signals, ", "), score)
	if score < th {
		return finding{detail: detail}
	}
	return finding{hit: true, detail: detail, reason: "looks like a prompt injection or jailbreak attempt"}
}

// injectionSignal is one weighted technique. Patterns run on normalized,
// lower-cased text (see normalizeForScan) unless caseSensitive is set, in which
// case they run on the folded text with its original case.
type injectionSignal struct {
	name          string
	weight        float64
	res           []*regexp.Regexp
	caseSensitive bool
}

// exfilQuery matches a query-string value that is a template placeholder or a
// parameter whose name suggests it carries conversation data.
const exfilQuery = `(?:[?&][^)\s"'>]*=[^)\s&"'>]*(?:\{|\[|<|%7b|%5b|\$)|[?&](?:data|secret|secrets|prompt|conversation|conv|chat|history|info|msg|message|exfil|leak|content|summary|password|pwd|key|token|q|d|p)=)`

var injectionSignals = func() []injectionSignal {
	re := regexp.MustCompile
	verbs := `(?:ignore|disregard|forget|override|bypass|do\s+not\s+(?:follow|obey)|don'?t\s+(?:follow|obey)|stop\s+following)`
	// "my" is deliberately absent: "disregard my previous instructions" is ordinary correspondence.
	scope := `(?:all|any|every|each|the|your|these|those|of|previous|prior|above|earlier|preceding|foregoing|original|initial|system|existing|developer|safety|\s)*`
	target := `(?:instructions?|prompts?|rules|directions|directives|guidelines|guidance|constraints|programming)`
	return []injectionSignal{
		{name: "instruction_override", weight: 0.6, res: []*regexp.Regexp{
			re(`\b` + verbs + `\s+` + scope + `(?:previous|prior|above|earlier|preceding|foregoing|original|initial|system|old|existing|developer|safety)\s+` + scope + target + `\b`),
			re(`\b(?:ignore|disregard|forget)\s+(?:all\s+(?:of\s+)?|everything\s+)(?:that\s+)?(?:(?:was|i|you)\s+)?(?:said|written|stated|told|wrote)?\s*(?:above|before|previously|so\s+far)\b`),
			re(`\b(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*(?::|follow|are)`),
			re(`\bfrom\s+now\s+on\s*,?\s+you\s+(?:will|must|are\s+to)\s+(?:only\s+)?(?:obey|follow|answer\s+as|respond\s+as|act\s+as)\b`),
		}},
		{name: "role_marker", weight: 0.5, res: []*regexp.Regexp{
			re(`<\|\s*im_start\s*\|>\s*(?:system|assistant)`),
			re(`<\|\s*(?:system|im_sep|endoftext|eot_id|start_header_id)\s*\|>`),
			re(`\[/?inst\]|<</?sys>>`),
			re(`(?m)^\s*#{2,}\s*(?:system|admin|developer)\s*(?:prompt|message|instructions?)?\s*:`),
			re(`(?m)^\s*\[?(?:system|admin|developer)\s*(?:prompt|message|override)?\]?\s*:\s*(?:you|ignore|from|new|the\s+(?:user|assistant))`),
			re(`</?(?:system|system_prompt)>`),
		}},
		{name: "persona_jailbreak", weight: 0.5, res: []*regexp.Regexp{
			re(`\bdo\s+anything\s+now\b`),
			re(`\bdeveloper\s+mode\s+(?:enabled|output|activated|on)\b|\b(?:simulate|pretend|act\s+as|enter|activate|enable)\b.{0,40}\bdeveloper\s+mode\b.{0,40}\b(?:no|without|uncensored|unfiltered|ignore)`),
			re(`\byou\s+(?:now\s+)?(?:have|has|are\s+under)\s+no\s+(?:restrictions|limitations|limits|rules|filters|guidelines|boundaries|constraints|ethics|morals)\b`),
			re(`\b(?:free|freed|liberated|released|unbound)\s+from\s+(?:all\s+|any\s+|the\s+)?(?:your\s+)?(?:typical\s+)?(?:restrictions|rules|guidelines|filters|constraints|confines|limitations|policies)\b`),
			re(`\b(?:without|ignoring|ignore)\s+(?:any\s+|all\s+|your\s+)?(?:ethical|moral|safety|content)\s+(?:guidelines|restrictions|constraints|filters|policies|considerations)\b`),
			re(`\b(?:act|behave|respond|pretend)\s+(?:as|like)\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|jailbroken|evil|unethical|amoral)\b`),
			re(`\b(?:jailbreak|jailbroken)\s+(?:mode|prompt|enabled|activated)\b|\benable\s+jailbreak\b`),
			re(`\bstay\s+in\s+character\b.{0,80}\b(?:no\s+matter|whatever|even\s+if)\b`),
		}},
		{name: "persona_dan", weight: 0.5, caseSensitive: true, res: []*regexp.Regexp{
			re(`\b(?:(?i:you\s+are|you're|act\s+as|pretend\s+to\s+be|become)\s+(?:now\s+)?DAN\b|DAN\s+(?i:mode|prompt|jailbreak))`),
		}},
		{name: "prompt_exfiltration", weight: 0.5, res: []*regexp.Regexp{
			re(`\b(?:reveal|print|show|output|repeat|display|tell|leak|dump|disclose|share|give|write\s+out|recite|echo|copy)\s+(?:me\s+|us\s+)?(?:all\s+|exactly\s+|verbatim\s+)?(?:of\s+)?(?:your|the|its)\s+(?:full\s+|entire\s+|complete\s+|exact\s+|original\s+|initial\s+|hidden\s+|secret\s+|internal\s+)*(?:system\s+(?:prompt|message|instructions?)|(?:initial|original|hidden|secret|internal|developer|pre-?)\s*(?:prompt|instructions?))`),
			re(`\bwhat\s+(?:are|were|is)\s+your\s+(?:system|initial|original|hidden|secret|internal)\s+(?:prompt|instructions?|rules|message)\b`),
			re(`\brepeat\s+(?:the\s+|all\s+)?(?:words|text|everything)\s+above\b|\b(?:print|output|repeat)\s+everything\s+(?:above|before)\s+(?:this|the\s+(?:first|user))`),
		}},
		{name: "exfiltration_link", weight: 0.6, res: []*regexp.Regexp{
			// Markdown image / link (images render automatically in chat UIs) whose query
			// string carries a template placeholder or a data-bearing parameter.
			re(`!?\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]*` + exfilQuery),
			re(`<(?:img|iframe|script|link|source)\b[^>]{0,200}\b(?:src|href)\s*=\s*["']?https?://[^"'\s>]*` + exfilQuery),
		}},
		{name: "markdown_image_query", weight: 0.3, res: []*regexp.Regexp{
			// Any auto-loading image whose URL has a query string.
			re(`!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]+\?[^)\s]*=[^)\s]*\)`),
			re(`<img\b[^>]{0,200}\bsrc\s*=\s*["']?https?://[^"'\s>]+\?[^"'\s>]*=`),
		}},
		{name: "url_data_instruction", weight: 0.25, res: []*regexp.Regexp{
			// Instructions to smuggle data into a URL.
			re(`\b(?:append|add|include|insert|put|encode)\b.{0,60}\b(?:to|in|into)\s+(?:the\s+|this\s+)?(?:url|link|query\s+string|image\s+url)\b`),
		}},
		{name: "encoding_instruction", weight: 0.3, res: []*regexp.Regexp{
			re(`\b(?:decode|decrypt|deobfuscate|translate)\s+(?:this|the\s+following|it|the\s+string)?\s*(?:from\s+)?(?:base64|base-64|b64|hex|rot13|rot-13)?\b.{0,40}\b(?:then\s+|and\s+)(?:follow|execute|obey|run|do|perform)\b`),
		}},
		{name: "multilingual_override", weight: 0.6, res: []*regexp.Regexp{
			// Spanish
			re(`\b(?:ignora|ignore|ignorar|olvida|olvide|olvidar|omite)\s+(?:todas?\s+)?(?:las\s+|tus\s+|sus\s+)?(?:instrucciones|indicaciones|reglas|ordenes|órdenes)\s+(?:anteriores|previas)`),
			// French
			re(`\b(?:ignore|ignorez|ignorer|oublie|oubliez|oublier)\s+(?:toutes\s+|tous\s+)?(?:les\s+|tes\s+|vos\s+)?(?:instructions|consignes|règles|regles|directives)\s+(?:précédentes|precedentes|antérieures|anterieures|ci-dessus)`),
			// German
			re(`\b(?:ignoriere|ignorier|ignorieren\s+sie|vergiss|vergessen\s+sie|missachte)\s+(?:alle\s+)?(?:die\s+|deine\s+|ihre\s+)?(?:vorherigen|bisherigen|vorigen|obigen|früheren|fruheren|vorangegangenen)\s+(?:anweisungen|instruktionen|regeln|befehle|anordnungen)`),
			// Portuguese
			re(`\b(?:ignore|ignora|ignorar|esqueça|esqueca|esquecer|desconsidere)\s+(?:todas\s+)?(?:as\s+|suas\s+)?(?:instruções|instrucoes|instrucões|regras|ordens)\s+(?:anteriores|prévias|previas)`),
			// Italian
			re(`\b(?:ignora|ignorate|dimentica|dimenticate|trascura)\s+(?:tutte\s+)?(?:le\s+)?(?:istruzioni|regole|indicazioni)\s+(?:precedenti|sopra|anteriori)`),
			// Chinese
			re(`(?:忽略|忽视|无视|忘记|忘掉|不要理会)(?:掉)?(?:你)?(?:之前|以上|上面|前面|先前|此前|所有|全部|一切)+(?:的)?(?:所有|全部)?(?:的)?(?:指令|指示|说明|规则|提示|要求)`),
			// Japanese
			re(`(?:以前|前|上記|これまで|先|今まで)の(?:すべての|全ての|全部の)?(?:指示|命令|ルール|指令|プロンプト)(?:を|は)?(?:すべて|全て)?(?:無視|忘れ)`),
		}},
	}
}()

// InjectionScore scores text for prompt-injection and jailbreak techniques.
// It returns a combined score in [0,1] (1 − Π(1 − weight) over the distinct
// signals found) and the sorted signal names.
func InjectionScore(text string) (float64, []string) {
	found := map[string]float64{}
	scanInjection(text, found, 0)
	if len(found) == 0 {
		return 0, nil
	}
	names := make([]string, 0, len(found))
	p := 1.0
	for n, w := range found {
		names = append(names, n)
		p *= 1 - w
	}
	sort.Strings(names)
	return math.Round((1-p)*100) / 100, names
}

const maxDecodeDepth = 2

func scanInjection(text string, found map[string]float64, depth int) {
	folded := foldText(text)
	lower := strings.ToLower(folded)
	variants := []string{collapseSpaced(lower)}
	if l := deLeet(variants[0]); l != variants[0] {
		variants = append(variants, l)
	}
	prefix := ""
	if depth > 0 {
		prefix = "encoded_"
	}
	for _, s := range injectionSignals {
		hay := variants
		if s.caseSensitive {
			hay = []string{folded}
		}
	match:
		for _, h := range hay {
			for _, r := range s.res {
				if r.MatchString(h) {
					w := s.weight
					if depth > 0 {
						// Hiding a technique inside an encoding is itself suspicious.
						w = math.Min(0.9, w+0.2)
					}
					if w > found[prefix+s.name] {
						found[prefix+s.name] = w
					}
					break match
				}
			}
		}
	}
	if depth < maxDecodeDepth {
		for _, dec := range decodedPayloads(text) {
			scanInjection(dec, found, depth+1)
		}
	}
}

var (
	b64CandRe = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
	hexCandRe = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}){16,}\b|(?:\\x[0-9a-fA-F]{2}){12,}`)
)

// decodedPayloads returns the printable text of long base64 / hex runs.
func decodedPayloads(text string) []string {
	var out []string
	for _, m := range hexCandRe.FindAllString(text, 20) {
		m = strings.ReplaceAll(m, `\x`, "")
		if b, err := hex.DecodeString(m); err == nil && printableText(b) {
			out = append(out, string(b))
		}
	}
	for _, m := range b64CandRe.FindAllString(text, 20) {
		if isAllHex(m) {
			continue
		}
		trim := strings.TrimRight(m, "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(trim); err == nil {
				if printableText(b) {
					out = append(out, string(b))
				}
				break
			}
		}
	}
	return out
}

func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isDigit(c) && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// printableText reports whether b is valid UTF-8 that is mostly letters and spaces.
func printableText(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	good, total := 0, 0
	for _, r := range string(b) {
		total++
		if unicode.IsLetter(r) || unicode.IsSpace(r) || unicode.IsDigit(r) || strings.ContainsRune(".,:;!?'\"-()[]<>|#/_", r) {
			good++
		} else if r < 32 || r == utf8.RuneError {
			return false
		}
	}
	return total > 0 && good*10 >= total*9
}

// homoglyphs folds common Cyrillic / Greek look-alikes to Latin letters.
var homoglyphs = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I',
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
	'ı': 'i', 'ℓ': 'l',
	'\u2018': '\'', '\u2019': '\'', '\u201C': '"', '\u201D': '"', '\u2013': '-', '\u2014': '-',
	'\u00A0': ' ', '\u2002': ' ', '\u2003': ' ', '\u2009': ' ', '\u3000': ' ',
}

// foldText applies an NFKC-style compatibility folding sufficient for scanning:
// removes zero-width and format characters, maps fullwidth ASCII, mathematical
// alphanumerics, enclosed letters and homoglyphs to plain ASCII.
func foldText(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\u00AD' || (r >= '\u200B' && r <= '\u200F') || (r >= '\u2060' && r <= '\u2064') || r == '\uFEFF' ||
			(r >= '\uFE00' && r <= '\uFE0F') || (r >= 0xE0000 && r <= 0xE007F) || r == '\u034F' || r == '\u180E':
			continue // invisible
		case r >= 0xFF01 && r <= 0xFF5E: // fullwidth ASCII
			sb.WriteRune(r - 0xFF01 + '!')
		case r >= 0x1D400 && r <= 0x1D6A3: // mathematical letters: 52 per style (A–Z a–z)
			k := (r - 0x1D400) % 52
			if k < 26 {
				sb.WriteRune('A' + k)
			} else {
				sb.WriteRune('a' + k - 26)
			}
		case r >= 0x1D7CE && r <= 0x1D7FF: // mathematical digits
			sb.WriteRune('0' + (r-0x1D7CE)%10)
		case r >= 0x24B6 && r <= 0x24CF: // circled capitals
			sb.WriteRune('A' + r - 0x24B6)
		case r >= 0x24D0 && r <= 0x24E9: // circled small letters
			sb.WriteRune('a' + r - 0x24D0)
		case r >= 0x1F130 && r <= 0x1F149: // squared capitals
			sb.WriteRune('A' + r - 0x1F130)
		case r >= 0x1F170 && r <= 0x1F189: // negative squared capitals
			sb.WriteRune('A' + r - 0x1F170)
		case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicators
			sb.WriteRune('A' + r - 0x1F1E6)
		default:
			if m, ok := homoglyphs[r]; ok {
				sb.WriteRune(m)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}

var (
	leetFold  = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")
	leetFoldL = strings.NewReplacer("0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "7", "t", "@", "a", "$", "s")
	// leetL lists words where "1" stands for "l" rather than "i".
	leetL = map[string]bool{"all": true, "tell": true, "rules": true, "rule": true, "role": true, "reveal": true, "developer": true,
		"guidelines": true, "filters": true, "limitations": true, "unfiltered": true, "follow": true, "will": true, "full": true,
		"model": true, "illegal": true, "please": true, "safely": true, "only": true, "really": true, "unlock": true, "unlocked": true}
)

// deLeet undoes simple leetspeak inside words (digits next to letters).
func deLeet(s string) string {
	return leetWordRe.ReplaceAllStringFunc(s, func(w string) string {
		if !strings.ContainsAny(w, "abcdefghijklmnopqrstuvwxyz") {
			return w // plain numbers stay numbers
		}
		if l := leetFoldL.Replace(w); leetL[l] {
			return l
		}
		return leetFold.Replace(w)
	})
}

var leetWordRe = regexp.MustCompile(`[a-z0-9@$]*[a-z][a-z0-9@$]*`)

var spacedRe = regexp.MustCompile(`\b(?:\p{L}[ .\-_*]){4,}\p{L}\b`)

// collapseSpaced joins letter-spaced words ("i g n o r e" → "ignore").
func collapseSpaced(s string) string {
	return spacedRe.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Map(func(r rune) rune {
			if strings.ContainsRune(" .-_*", r) {
				return -1
			}
			return r
		}, m)
	})
}
