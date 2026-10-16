package guardrails

import (
	"regexp"
	"strings"
)

// Category is a built-in content category usable by blocklist guardrails.
//
// Categories focus on harmful intent expressed as phrases (requests for weapons,
// self-harm statements, threats, dehumanizing statements) rather than long word
// dictionaries, which keeps false positives low on ordinary text. Identity-based
// slurs are deliberately not shipped: add your own terms to the guardrail's word
// list, or pair the category with a guard model, which recognizes them far more
// reliably in context.
type Category struct {
	ID          string
	Label       string
	Description string
	// Terms are single words or short phrases matched on word boundaries with
	// tolerance for case, leetspeak and separators (e.g. "s.h.1.t").
	Terms []string
	// Patterns are case-insensitive regular expressions for phrase-level intent.
	Patterns []string
}

// ContentCategories lists the built-in categories in display order.
var ContentCategories = []Category{
	{
		ID: "profanity", Label: "Profanity",
		Description: "Common swear words and crude insults (obfuscated spellings included).",
		Terms: []string{"fuck", "fucking", "fucker", "motherfucker", "fucked", "shit", "shitty", "bullshit", "bitch",
			"asshole", "bastard", "dickhead", "prick", "twat", "wanker", "bollocks", "cunt", "piss off", "son of a bitch", "jackass", "dumbass"},
	},
	{
		ID: "sexual", Label: "Sexual content",
		Description: "Explicit sexual terms and requests for pornographic material.",
		Terms: []string{"porn", "porno", "pornography", "pornographic", "hardcore porn", "xxx video", "blowjob", "handjob",
			"cumshot", "gangbang", "sex tape", "nude pics", "send nudes", "explicit sex", "erotic roleplay", "camgirl", "onlyfans leak"},
		Patterns: []string{
			`\b(write|describe|generate)\b.{0,40}\b(explicit|graphic|hardcore)\b.{0,20}\b(sex|sexual)\b`,
		},
	},
	{
		ID: "hate", Label: "Hate speech",
		Description: "Dehumanizing statements and calls for violence or exclusion against groups.",
		Patterns: []string{
			`\b(all|those|these|the)\s+\w+s?\s+(are|r)\s+(animals|vermin|subhuman|parasites|cockroaches|rats|savages|a disease|a plague)\b`,
			`\b(exterminate|eradicate|wipe out|gas|deport all)\s+(all|the|every|those)\s+\w+`,
			`\b\w+s?\s+(should|must|deserve to)\s+(all\s+)?(die|be killed|be exterminated|be wiped out|be gassed|hang)\b`,
			`\b(white power|race war now|ethnic cleansing now|master race|14 words|heil hitler|sieg heil)\b`,
		},
	},
	{
		ID: "harassment", Label: "Harassment & threats",
		Description: "Threats, intimidation and encouragement of self-harm aimed at a person.",
		Terms:       []string{"kill yourself", "kys", "go die", "nobody would miss you", "you deserve to die", "drink bleach"},
		Patterns: []string{
			`\bi\s*('?ll|will|am going to|'?m gonna|gonna)\s+(find|hunt down|hurt|kill|beat|rape|stab|shoot)\s+(you|u|your family)\b`,
			`\b(i know where you live|watch your back)\b`,
		},
	},
	{
		ID: "self_harm", Label: "Self-harm",
		Description: "Statements of suicidal intent or requests for self-harm methods.",
		Terms:       []string{"kill myself", "end my life", "want to die", "suicide note", "cut myself", "hang myself", "self harm", "self-harm"},
		Patterns: []string{
			`\b(how|best way|easiest way|painless way)\b.{0,30}\b(kill myself|commit suicide|end my life|overdose on)\b`,
			`\bhow (much|many)\b.{0,30}\b(pills|tablets)\b.{0,30}\b(to die|lethal|fatal|overdose)\b`,
		},
	},
	{
		ID: "violence", Label: "Violence",
		Description: "Requests to plan or carry out violence against people.",
		Terms:       []string{"hire a hitman", "mass shooting plan", "school shooting plan"},
		Patterns: []string{
			`\bhow (to|do i|can i|would i)\b.{0,20}\b(kill|murder|torture|poison|strangle|kidnap)\b.{0,20}\b(someone|a person|people|my|him|her|them|a child)\b`,
			`\b(get away with|cover up)\b.{0,10}\b(murder|killing)\b`,
			`\b(dispose of|get rid of|hide)\b.{0,15}\b(a|the)\s+body\b`,
		},
	},
	{
		ID: "weapons", Label: "Weapons & explosives",
		Description: "Instructions for building weapons, explosives or chemical/biological agents.",
		Terms:       []string{"pipe bomb", "molotov cocktail", "ghost gun", "auto sear", "nerve agent"},
		Patterns: []string{
			`\bhow (to|do i|can i)\b.{0,20}\b(make|build|assemble|construct)\b.{0,20}\b(a\s+)?(bomb|explosive|ied|detonator|grenade|napalm|thermite)s?([\s.,!?;:]|$)`,
			`\b(3d[- ]?print(ed)?|untraceable)\b.{0,15}\b(gun|firearm|pistol|rifle|receiver)\b`,
			`\bconvert\b.{0,30}\b(full[- ]?auto|automatic)\b`,
			`\b(make|produce|synthesi[sz]e|culture|weaponi[sz]e)\b.{0,20}\b(ricin|sarin|vx gas|anthrax|botulinum|mustard gas|chlorine gas)\b`,
		},
	},
	{
		ID: "drugs", Label: "Illegal drugs",
		Description: "Synthesis of controlled substances and buying drugs illicitly.",
		Patterns: []string{
			`\b(how to|recipe for|steps to)\b.{0,20}\b(make|cook|synthesi[sz]e|extract|produce)\b.{0,20}\b(meth|methamphetamine|fentanyl|heroin|cocaine|crack|lsd|mdma|ghb|dmt)\b`,
			`\b(buy|order|purchase|source)\b.{0,20}\b(cocaine|heroin|fentanyl|meth|mdma|lsd)\b.{0,20}\b(online|dark ?web|darknet|without a prescription)\b`,
		},
	},
	{
		ID: "extremism", Label: "Violent extremism",
		Description: "Recruitment, glorification or planning of terrorist and violent extremist activity.",
		Terms:       []string{"lone wolf attack", "join the caliphate", "martyrdom operation"},
		Patterns: []string{
			`\b(join|recruit(ing)? for|pledge allegiance to)\b.{0,15}\b(isis|isil|al[- ]?qaeda|daesh|al[- ]?shabaab|the base)\b`,
			`\b(plan|planning|carry out|organi[sz]e)\b.{0,20}\b(terrorist attack|terror attack|bombing campaign)\b`,
		},
	},
}

// CategoryByID returns a built-in content category.
func CategoryByID(id string) (Category, bool) {
	for _, c := range ContentCategories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// AllCategoryIDs returns every built-in category id.
func AllCategoryIDs() []string {
	out := make([]string, len(ContentCategories))
	for i, c := range ContentCategories {
		out[i] = c.ID
	}
	return out
}

// leet lists the obfuscated forms accepted for each letter of a category term.
var leet = map[rune]string{
	'a': "a@4", 'b': "b8", 'e': "e3", 'g': "g9", 'i': "i1!|l", 'l': "l1|", 'o': "o0", 's': "s$5", 't': "t7+", 'z': "z2",
}

// obfuscatedTerm builds a regex for a term that tolerates case, leetspeak, repeated
// letters and single separators between letters ("f.u.c.k", "sh1t", "fuuuck").
func obfuscatedTerm(term string) string {
	words := strings.Fields(strings.ToLower(term))
	parts := make([]string, len(words))
	for wi, w := range words {
		var b strings.Builder
		runes := []rune(w)
		for i, r := range runes {
			class := regexp.QuoteMeta(string(r))
			if alts, ok := leet[r]; ok {
				class = "[" + regexp.QuoteMeta(alts) + "]"
			}
			b.WriteString(class + "+")
			if i < len(runes)-1 {
				b.WriteString(`[._\-*]?`)
			}
		}
		parts[wi] = b.String()
	}
	return strings.Join(parts, `[\s._\-]+`)
}

// categoryPatterns compiles the selected categories into one pattern per category.
func categoryPatterns(ids []string, repl string) ([]compiledPattern, error) {
	var out []compiledPattern
	for _, id := range ids {
		c, ok := CategoryByID(id)
		if !ok {
			continue
		}
		var alts []string
		for _, t := range c.Terms {
			alts = append(alts, `(?:^|[^\pL\pN])(`+obfuscatedTerm(t)+`)(?:$|[^\pL\pN])`)
		}
		for _, p := range c.Patterns {
			alts = append(alts, `(`+p+`)`)
		}
		if len(alts) == 0 {
			continue
		}
		re, err := regexp.Compile(`(?i)` + strings.Join(alts, "|"))
		if err != nil {
			return nil, err
		}
		out = append(out, compiledPattern{re: re, repl: repl, src: "category:" + c.ID})
	}
	return out, nil
}

// replaceCategory masks only the matched term inside a category match, keeping the
// boundary characters consumed by the term alternation.
func replaceCategory(re *regexp.Regexp, text, repl string, hit func()) string {
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
		// Find the innermost participating group: the actual term/phrase span.
		start, end := m[0], m[1]
		for g := 1; g*2 < len(m); g++ {
			if m[g*2] >= 0 {
				start, end = m[g*2], m[g*2+1]
				break
			}
		}
		if start < last {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString(repl)
		last = end
		hit()
	}
	b.WriteString(text[last:])
	return b.String()
}
