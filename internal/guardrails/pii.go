package guardrails

import (
	"regexp"
	"strings"
)

// PII entity identifiers accepted in a pii guardrail's config. The regional
// library adds many more (see pii_regional.go); every id is listed in Entities.
const (
	EntityEmail      = "email"
	EntityPhone      = "phone"
	EntitySSN        = "ssn"
	EntityCreditCard = "credit_card"
	EntityIPv4       = "ipv4"
	EntitySecret     = "secret"
)

// Entity group names, in display order (see EntityGroups).
const (
	GroupCore      = "Core"
	GroupUS        = "United States"
	GroupUK        = "United Kingdom"
	GroupEU        = "European Union"
	GroupCanada    = "Canada"
	GroupAustralia = "Australia"
	GroupFinancial = "Financial"
	GroupHealth    = "Health"
	GroupNetwork   = "Network & credentials"
	GroupPersonal  = "Personal"
)

// Entity describes one built-in PII detector.
type Entity struct {
	ID    string
	Label string
	Mask  string
	Hint  string
	Group string
	// Context is true when the entity is only detected near a keyword
	// (e.g. "passport", "routing number") because its format alone is ambiguous.
	Context bool
}

// EntityGroups returns the entity group names in display order.
func EntityGroups() []string {
	return []string{GroupCore, GroupUS, GroupUK, GroupEU, GroupCanada, GroupAustralia,
		GroupFinancial, GroupHealth, GroupNetwork, GroupPersonal}
}

// Entities lists the built-in PII detectors grouped for display (see EntityGroups).
// Detection runs in a different, fixed order (detectionOrder) so specific formats
// win over generic ones.
var Entities = []Entity{
	// Core
	{ID: EntityEmail, Label: "Email addresses", Mask: "[EMAIL]", Hint: "name@example.com", Group: GroupCore},
	{ID: EntityPhone, Label: "Phone numbers", Mask: "[PHONE]", Hint: "+1 415 555 0100, (415) 555-0100, +44 20 7946 0958", Group: GroupCore},

	// United States
	{ID: EntitySSN, Label: "US social security numbers", Mask: "[SSN]", Hint: "123-45-6789 (invalid ranges ignored; undashed only near \"SSN\")", Group: GroupUS},
	{ID: EntityUSITIN, Label: "US ITIN", Mask: "[US_ITIN]", Hint: "9XX-7X-XXXX taxpayer numbers (valid group ranges)", Group: GroupUS},
	{ID: EntityUSPassport, Label: "US passport numbers", Mask: "[US_PASSPORT]", Hint: "9 digits or letter + 8 digits, near \"passport\"", Group: GroupUS, Context: true},
	{ID: EntityUSDriversLicense, Label: "US driver's licenses", Mask: "[US_DRIVERS_LICENSE]", Hint: "state formats, near \"driver's license\" / \"DL\"", Group: GroupUS, Context: true},
	{ID: EntityUSBankRouting, Label: "US bank routing numbers", Mask: "[US_BANK_ROUTING]", Hint: "ABA checksum, near \"routing\" / \"ABA\"", Group: GroupUS, Context: true},
	{ID: EntityUSEIN, Label: "US employer ID (EIN)", Mask: "[US_EIN]", Hint: "12-3456789, near \"EIN\" / \"tax id\"", Group: GroupUS, Context: true},

	// United Kingdom
	{ID: EntityUKNINO, Label: "UK National Insurance numbers", Mask: "[UK_NINO]", Hint: "QQ 12 34 56 C (prefix rules)", Group: GroupUK},
	{ID: EntityUKNHS, Label: "UK NHS numbers", Mask: "[UK_NHS]", Hint: "943 476 5919 (mod-11), near \"NHS\"", Group: GroupUK, Context: true},
	{ID: EntityUKPostcode, Label: "UK postcodes", Mask: "[UK_POSTCODE]", Hint: "SW1A 1AA", Group: GroupUK},
	{ID: EntityUKSortCode, Label: "UK bank sort codes", Mask: "[UK_SORT_CODE]", Hint: "12-34-56, near \"sort code\"", Group: GroupUK, Context: true},

	// European Union
	{ID: EntityIBAN, Label: "IBAN bank accounts", Mask: "[IBAN]", Hint: "all countries, length + mod-97 checked", Group: GroupEU},
	{ID: EntityEUVAT, Label: "EU VAT numbers", Mask: "[EU_VAT]", Hint: "DE123456789, FRXX123456789, NL123456789B01 ...", Group: GroupEU},
	{ID: EntityFRNIR, Label: "French social security (NIR)", Mask: "[FR_NIR]", Hint: "15 digits with control key", Group: GroupEU},
	{ID: EntityDETaxID, Label: "German tax ID (Steuer-IdNr)", Mask: "[DE_TAX_ID]", Hint: "11 digits, checksum, near \"Steuer-ID\" / \"IdNr\"", Group: GroupEU, Context: true},
	{ID: EntityESDNI, Label: "Spanish DNI", Mask: "[ES_DNI]", Hint: "12345678Z (check letter)", Group: GroupEU},
	{ID: EntityESNIE, Label: "Spanish NIE", Mask: "[ES_NIE]", Hint: "X1234567L (check letter)", Group: GroupEU},
	{ID: EntityITFiscalCode, Label: "Italian fiscal code", Mask: "[IT_FISCAL_CODE]", Hint: "RSSMRA85T10A562S (check character)", Group: GroupEU},
	{ID: EntityNLBSN, Label: "Dutch BSN", Mask: "[NL_BSN]", Hint: "1234.56.782, or 9 digits near \"BSN\" (11-proof)", Group: GroupEU},
	{ID: EntityPLPESEL, Label: "Polish PESEL", Mask: "[PL_PESEL]", Hint: "11 digits, date + checksum", Group: GroupEU},

	// Canada
	{ID: EntityCASIN, Label: "Canadian SIN", Mask: "[CA_SIN]", Hint: "046 454 286 (Luhn); undashed only near \"SIN\"", Group: GroupCanada},
	{ID: EntityCAHealthCard, Label: "Canadian health cards", Mask: "[CA_HEALTH_CARD]", Hint: "OHIP / RAMQ / PHN formats, near \"health card\"", Group: GroupCanada, Context: true},
	{ID: EntityCAPostalCode, Label: "Canadian postal codes", Mask: "[CA_POSTAL_CODE]", Hint: "K1A 0B1", Group: GroupCanada},

	// Australia
	{ID: EntityAUTFN, Label: "Australian tax file numbers", Mask: "[AU_TFN]", Hint: "123 456 782 (checksum); undashed only near \"TFN\"", Group: GroupAustralia},
	{ID: EntityAUABN, Label: "Australian business numbers", Mask: "[AU_ABN]", Hint: "51 824 753 556 (mod-89)", Group: GroupAustralia},
	{ID: EntityAUMedicare, Label: "Australian Medicare numbers", Mask: "[AU_MEDICARE]", Hint: "2123 45670 1 (checksum); undashed only near \"Medicare\"", Group: GroupAustralia},

	// Financial
	{ID: EntityCreditCard, Label: "Credit card numbers", Mask: "[CREDIT_CARD]", Hint: "13–19 digits, Luhn-validated", Group: GroupFinancial},
	{ID: EntitySWIFTBIC, Label: "SWIFT / BIC codes", Mask: "[SWIFT_BIC]", Hint: "DEUTDEFF500, near \"SWIFT\" / \"BIC\"", Group: GroupFinancial, Context: true},
	{ID: EntityCryptoWallet, Label: "Crypto wallet addresses", Mask: "[CRYPTO_WALLET]", Hint: "Bitcoin (base58check / bech32 checksum), Ethereum 0x…", Group: GroupFinancial},

	// Health
	{ID: EntityUSNPI, Label: "US provider numbers (NPI)", Mask: "[US_NPI]", Hint: "10 digits, Luhn with 80840 prefix, near \"NPI\"", Group: GroupHealth, Context: true},
	{ID: EntityUSDEA, Label: "US DEA registration numbers", Mask: "[US_DEA]", Hint: "AB1234563 (checksum)", Group: GroupHealth},
	{ID: EntityMedicalRecord, Label: "Medical record numbers", Mask: "[MEDICAL_RECORD_NUMBER]", Hint: "near \"MRN\" / \"medical record\" / \"patient ID\"", Group: GroupHealth, Context: true},
	{ID: EntityHealthInsurance, Label: "Health insurance IDs", Mask: "[HEALTH_INSURANCE_ID]", Hint: "Medicare MBI format, or IDs near \"member ID\" / \"policy number\"", Group: GroupHealth, Context: true},

	// Network & credentials
	{ID: EntitySecret, Label: "Secrets & API keys", Mask: "[SECRET]", Hint: "sk-/lg- style keys, access key IDs, tokens, JWTs, private keys, key=value secrets", Group: GroupNetwork},
	{ID: EntityIPv4, Label: "IPv4 addresses", Mask: "[IP_ADDRESS]", Hint: "192.168.0.10", Group: GroupNetwork},
	{ID: EntityIPv6, Label: "IPv6 addresses", Mask: "[IP_ADDRESS]", Hint: "2001:db8::8a2e:370:7334", Group: GroupNetwork},
	{ID: EntityMACAddress, Label: "MAC addresses", Mask: "[MAC_ADDRESS]", Hint: "00:1A:2B:3C:4D:5E", Group: GroupNetwork},
	{ID: EntityURLCredentials, Label: "Credentials in URLs", Mask: "[URL_CREDENTIALS]", Hint: "https://user:pass@host", Group: GroupNetwork},
	{ID: EntityConnectionString, Label: "Database connection strings", Mask: "[CONNECTION_STRING]", Hint: "postgres://u:p@host/db, Server=…;Password=…", Group: GroupNetwork},

	// Personal
	{ID: EntityDateOfBirth, Label: "Dates of birth", Mask: "[DATE_OF_BIRTH]", Hint: "dates near \"DOB\" / \"date of birth\" / \"born on\"", Group: GroupPersonal, Context: true},
	{ID: EntityStreetAddress, Label: "Street addresses", Mask: "[STREET_ADDRESS]", Hint: "123 Main Street, Apt 4", Group: GroupPersonal},
}

// detectionOrder is the order entities are applied in: credentials first (they
// can contain anything), then checksummed or strongly structured identifiers,
// then keyword-anchored ones, then generic numeric shapes, then phone numbers.
// Each pass sees the text already masked by earlier passes.
var detectionOrder = []string{
	EntityConnectionString, EntityURLCredentials, EntitySecret, EntityEmail, EntityCryptoWallet,
	EntityIBAN, EntityEUVAT, EntitySWIFTBIC, EntityIPv6, EntityMACAddress, EntityIPv4,
	EntityFRNIR, EntityCreditCard, EntityITFiscalCode, EntityESNIE, EntityESDNI, EntityUKNINO, EntityUSDEA,
	EntityDateOfBirth, EntityUSBankRouting, EntityUSPassport, EntityUSEIN, EntityUSDriversLicense,
	EntityUKSortCode, EntityUKNHS, EntityDETaxID, EntityUSNPI, EntityAUMedicare, EntityCAHealthCard,
	EntityMedicalRecord, EntityHealthInsurance,
	EntityUSITIN, EntitySSN, EntityCASIN, EntityAUTFN, EntityNLBSN, EntityPLPESEL, EntityAUABN,
	EntityUKPostcode, EntityCAPostalCode, EntityStreetAddress, EntityPhone,
}

// detector is one pattern of an entity.
type detector struct {
	entity string
	mask   string
	re     *regexp.Regexp
	// group, when >0, is the capture group that is masked; the rest of the match
	// is kept (e.g. the "api_key=" in front of a secret).
	group int
	// find, when set, replaces re: it returns [start, end) spans of values.
	find     func(string) [][2]int
	validate func(string) bool
	// ctx, when set, must match near the value (see hasContext).
	ctx *regexp.Regexp
	// notCtx, when set, must not match near the value: it hands an ambiguous
	// shape to another entity whose keyword is present (e.g. a TFN near "TFN").
	notCtx *regexp.Regexp
	// numeric rejects values glued to a larger number ("+4412…", "3.123456789").
	numeric bool
}

var detectors = func() map[string][]detector {
	octet := `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`
	m := map[string][]detector{
		EntitySecret: {
			{re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
			{re: regexp.MustCompile(`\b(?:sk|pk|rk|lg)-[A-Za-z0-9_\-]{16,}`)},
			{re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
			{re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`)},
			{re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
			{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
			{re: regexp.MustCompile(`(?i)\b((?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["']?)([^\s"',;]{8,})`), group: 2},
		},
		EntityEmail: {
			{re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)},
		},
		EntityCreditCard: {
			// The prefix group keeps "+<digits>" (international phone numbers) out of card matches.
			{re: regexp.MustCompile(`(^|[^+\d])(\d(?:[ -]?\d){12,18})\b`), validate: validCard, group: 2},
		},
		EntitySSN: {
			{re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), validate: validSSN, numeric: true},
			{re: regexp.MustCompile(`\b\d{9}\b`), validate: validSSN, numeric: true,
				ctx: regexp.MustCompile(`(?i)\b(?:SSN|social\s+security(?:\s+(?:number|no))?)\b`)},
		},
		EntityPhone: {
			{re: regexp.MustCompile(`(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)\s?|\b\d{3}[\s.-])\d{3}[\s.-]\d{4}\b`)},
			{re: regexp.MustCompile(`\+\d{8,15}\b`)},
			// International with grouping: +44 20 7946 0958, +33 1 23 45 67 89.
			{re: regexp.MustCompile(`\+\d{1,3}(?:[ .-]\(?\d{1,4}\)?){2,6}\b`), validate: digitCount(8, 15)},
		},
		EntityIPv4: {
			{re: regexp.MustCompile(`\b` + octet + `\.` + octet + `\.` + octet + `\.` + octet + `\b`)},
		},
	}
	for id, ds := range regionalDetectors() {
		m[id] = append(m[id], ds...)
	}
	for _, e := range Entities {
		ds := m[e.ID]
		for i := range ds {
			ds[i].entity, ds[i].mask = e.ID, e.Mask
		}
	}
	return m
}()

// AllEntityIDs returns every built-in entity id, in display order.
func AllEntityIDs() []string {
	out := make([]string, len(Entities))
	for i, e := range Entities {
		out[i] = e.ID
	}
	return out
}

func entityMask(id string) string {
	for _, e := range Entities {
		if e.ID == id {
			return e.Mask
		}
	}
	return "[REDACTED]"
}

// MaskPII replaces every occurrence of the given entities (all when empty) with
// its mask token and returns the masked text plus per-entity match counts.
func MaskPII(text string, entities []string) (string, map[string]int) {
	if len(entities) == 0 {
		entities = AllEntityIDs()
	}
	want := map[string]bool{}
	for _, e := range entities {
		want[e] = true
	}
	var counts map[string]int
	for _, id := range detectionOrder {
		if !want[id] {
			continue
		}
		for _, d := range detectors[id] {
			text = d.replace(text, func() {
				if counts == nil {
					counts = map[string]int{}
				}
				counts[d.entity]++
			})
		}
	}
	return text, counts
}

// span is one candidate value: the mask covers [vs, ve).
type span struct{ vs, ve int }

func (d detector) spans(text string) []span {
	if d.find != nil {
		f := d.find(text)
		out := make([]span, len(f))
		for i, s := range f {
			out[i] = span{s[0], s[1]}
		}
		return out
	}
	locs := d.re.FindAllStringSubmatchIndex(text, -1)
	out := make([]span, 0, len(locs))
	for _, loc := range locs {
		if d.group > 0 {
			if loc[2*d.group] < 0 {
				continue
			}
			out = append(out, span{loc[2*d.group], loc[2*d.group+1]})
		} else {
			out = append(out, span{loc[0], loc[1]})
		}
	}
	return out
}

func (d detector) replace(text string, hit func()) string {
	if d.ctx != nil && !d.ctx.MatchString(text) {
		return text // cheap pre-check: no keyword anywhere
	}
	cands := d.spans(text)
	if len(cands) == 0 {
		return text
	}
	var sb strings.Builder
	last := 0
	for _, c := range cands {
		v := text[c.vs:c.ve]
		if d.numeric && gluedNumber(text, c.vs, c.ve) {
			continue
		}
		if d.validate != nil && !d.validate(v) {
			continue
		}
		if d.ctx != nil && !hasContext(text, c.vs, c.ve, d.ctx) {
			continue
		}
		if d.notCtx != nil && hasContext(text, c.vs, c.ve, d.notCtx) {
			continue
		}
		sb.WriteString(text[last:c.vs])
		sb.WriteString(d.mask)
		last = c.ve
		hit()
	}
	if last == 0 {
		return text
	}
	sb.WriteString(text[last:])
	return sb.String()
}

// Context windows (bytes) searched for an entity's keyword around a value.
const (
	ctxBefore = 64
	ctxAfter  = 32
)

// hasContext reports whether the keyword regexp matches shortly before or after
// the value. The window stops at line breaks, earlier masks and other numbers, so
// in "passport 123456789, routing 021000021" each value sees only its own keyword.
func hasContext(text string, vs, ve int, kw *regexp.Regexp) bool {
	lo := max(0, vs-ctxBefore)
	before := text[lo:vs]
	digits := 0
	for i := len(before) - 1; i >= 0; i-- {
		c := before[i]
		if c >= '0' && c <= '9' {
			digits++
			if digits >= 3 {
				before = before[i+1:]
				break
			}
			continue
		}
		digits = 0
		if c == '\n' || c == ']' {
			before = before[i+1:]
			break
		}
	}
	if kw.MatchString(before) {
		return true
	}
	hi := min(len(text), ve+ctxAfter)
	after := text[ve:hi]
	for i := 0; i < len(after); i++ {
		c := after[i]
		if c == '\n' || c == '[' || (c >= '0' && c <= '9') {
			after = after[:i]
			break
		}
	}
	return kw.MatchString(after)
}

// gluedNumber reports whether [vs,ve) is part of a larger number: preceded by
// '+' (phone numbers), continued by a decimal / thousands separator and digit,
// or adjacent to another space-separated digit group.
func gluedNumber(text string, vs, ve int) bool {
	if vs > 0 {
		p := text[vs-1]
		if p == '+' {
			return true
		}
		if (p == '.' || p == ',') && vs > 1 && isDigit(text[vs-2]) {
			return true
		}
	}
	if ve < len(text)-1 {
		n := text[ve]
		if (n == '.' || n == ',') && isDigit(text[ve+1]) {
			return true
		}
		// Space-grouped numbers ("11 222 333 444"): a neighbouring digit group.
		if n == ' ' && isDigit(text[ve+1]) {
			return true
		}
	}
	if vs > 1 && text[vs-1] == ' ' && isDigit(text[vs-2]) {
		return true
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// onlyDigits strips everything but ASCII digits.
func onlyDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func digitCount(lo, hi int) func(string) bool {
	return func(s string) bool {
		n := len(onlyDigits(s))
		return n >= lo && n <= hi
	}
}

// Luhn reports whether a digit string passes the Luhn checksum.
func Luhn(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum, dbl := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if dbl {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		dbl = !dbl
	}
	return sum%10 == 0
}

func validCard(s string) bool {
	digits := onlyDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	// Reject runs of a single repeated digit (e.g. 0000 0000 0000 0000), which pass Luhn.
	if repeated(digits) {
		return false
	}
	return Luhn(digits)
}

func validSSN(s string) bool {
	d := onlyDigits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[0:3], d[3:5], d[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	return group != "00" && serial != "0000"
}

// repeated reports whether s is one character repeated.
func repeated(s string) bool { return s != "" && strings.Count(s, s[:1]) == len(s) }
