package guardrails

import (
	"net"
	"regexp"
	"strings"
)

// Regional and extended PII entity ids.
const (
	EntityUSITIN           = "us_itin"
	EntityUSPassport       = "us_passport"
	EntityUSDriversLicense = "us_drivers_license"
	EntityUSBankRouting    = "us_bank_routing"
	EntityUSEIN            = "us_ein"

	EntityUKNINO     = "uk_nino"
	EntityUKNHS      = "uk_nhs"
	EntityUKPostcode = "uk_postcode"
	EntityUKSortCode = "uk_sort_code"

	EntityIBAN         = "iban"
	EntityEUVAT        = "eu_vat"
	EntityFRNIR        = "fr_nir"
	EntityDETaxID      = "de_tax_id"
	EntityESDNI        = "es_dni"
	EntityESNIE        = "es_nie"
	EntityITFiscalCode = "it_fiscal_code"
	EntityNLBSN        = "nl_bsn"
	EntityPLPESEL      = "pl_pesel"

	EntityCASIN        = "ca_sin"
	EntityCAHealthCard = "ca_health_card"
	EntityCAPostalCode = "ca_postal_code"

	EntityAUTFN      = "au_tfn"
	EntityAUABN      = "au_abn"
	EntityAUMedicare = "au_medicare"

	EntitySWIFTBIC     = "swift_bic"
	EntityCryptoWallet = "crypto_wallet"

	EntityUSNPI           = "us_npi"
	EntityUSDEA           = "us_dea"
	EntityMedicalRecord   = "medical_record_number"
	EntityHealthInsurance = "health_insurance_id"

	EntityIPv6             = "ipv6"
	EntityMACAddress       = "mac_address"
	EntityURLCredentials   = "url_credentials"
	EntityConnectionString = "connection_string"

	EntityDateOfBirth   = "date_of_birth"
	EntityStreetAddress = "street_address"
)

func kw(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

var tfnKeyword = kw(`(?i)\b(?:TFN|tax\s+file\s+(?:number|no))\b`)

func regionalDetectors() map[string][]detector {
	re := regexp.MustCompile
	months := `(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)`
	streetWord := `(?:[A-Z][A-Za-z'.-]*|\d+(?:st|nd|rd|th))`
	streetSuffix := `(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Square|Sq|Trail|Trl|Alley|Plaza|Crescent|Close)`
	dbSchemes := `(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|oracle|cockroachdb|clickhouse|couchdb|neo4j(?:\+s)?|cassandra|jdbc:[a-z0-9]+)`
	adoKeys := `(?:server|data\s+source|host|address|addr|network\s+address|database|initial\s+catalog|uid|user\s+id|user|username|port|provider|driver|dsn|encrypt|trusted_connection|integrated\s+security|sslmode|timeout|connect(?:ion)?\s+timeout|persist\s+security\s+info|multipleactiveresultsets|trustservercertificate|application\s+name)`

	streetRe := re(`\b\d{1,6}[A-Z]?\s+(?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West)\.?\s+)?(?:` + streetWord + `\s+){0,3}` + streetWord + `\s+(` + streetSuffix + `)\b\.?((?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|Fl|Floor)\.?\s*#?\s*[A-Za-z0-9-]+|,?\s*#\s*[A-Za-z0-9-]+)?)`)

	return map[string][]detector{
		// --- United States ---
		EntityUSITIN: {
			{re: re(`\b9\d{2}[- ]\d{2}[- ]\d{4}\b`), validate: validITIN, numeric: true},
			{re: re(`\b9\d{8}\b`), validate: validITIN, numeric: true, ctx: kw(`(?i)\b(?:ITIN|individual\s+taxpayer)\b`)},
		},
		EntityUSPassport: {
			{re: re(`\b(?:[A-Z]\d{8}|\d{9})\b`), numeric: true, ctx: kw(`(?i)\bpassport\b`)},
		},
		EntityUSDriversLicense: {
			{re: re(`\b(?:[A-Z]\d{3}[- ]\d{3}[- ]\d{2}[- ]\d{3}[- ]\d|[A-Z]\d{3}[- ]?\d{4}[- ]?\d{4}|[A-Z]{1,2}[- ]?\d{4,14}|\d{6,13})\b`), numeric: true,
				ctx: kw(`(?i)(?:\bdriver'?s?\s+licen[cs]e|\bdriving\s+licen[cs]e|\bDL\b|\bD\.L\.|\bDLN\b|\blicen[cs]e\s*(?:no\.?|num(?:ber)?|#))`)},
		},
		EntityUSBankRouting: {
			{re: re(`\b\d{9}\b`), validate: validABA, numeric: true,
				ctx: kw(`(?i)\b(?:routing|ABA|RTN|transit\s+(?:number|no))\b`)},
		},
		EntityUSEIN: {
			{re: re(`\b\d{2}-?\d{7}\b`), validate: validEIN, numeric: true,
				ctx: kw(`(?i)\b(?:EIN|FEIN|employer\s+(?:identification|id)|tax\s+id(?:entification)?|TIN|federal\s+tax)\b`)},
		},

		// --- United Kingdom ---
		EntityUKNINO: {
			{re: re(`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b`), validate: validNINO},
		},
		EntityUKNHS: {
			{re: re(`\b\d{3}[ -]?\d{3}[ -]?\d{4}\b`), validate: validNHS, numeric: true,
				ctx: kw(`(?i)\b(?:NHS|national\s+health|health\s+service)\b`)},
		},
		EntityUKPostcode: {
			{re: re(`\b(?:GIR 0AA|(?:[A-PR-UWYZ][0-9][0-9]?|[A-PR-UWYZ][A-HK-Y][0-9][0-9]?|[A-PR-UWYZ][0-9][A-HJKPSTUW]|[A-PR-UWYZ][A-HK-Y][0-9][ABEHMNPRVWXY]) [0-9][ABD-HJLNP-UW-Z]{2})\b`)},
		},
		EntityUKSortCode: {
			{re: re(`\b\d{2}[- ]?\d{2}[- ]?\d{2}\b`), numeric: true, ctx: kw(`(?i)\bsort\s*code\b`)},
		},

		// --- European Union ---
		EntityIBAN: {
			{find: findIBANs},
		},
		EntityEUVAT: {
			{re: re(`\b(?:ATU\d{8}|BE ?[01]\d{9}|BG ?\d{9,10}|CY ?\d{8}[A-Z]|CZ ?\d{8,10}|DE ?\d{9}|DK ?\d{8}|EE ?\d{9}|EL ?\d{9}|ES ?[A-Z0-9]\d{7}[A-Z0-9]|FI ?\d{8}|FR ?[A-HJ-NP-Z0-9]{2}\d{9}|HR ?\d{11}|HU ?\d{8}|IE ?\d[A-Z0-9+*]\d{5}[A-Z]{1,2}|IT ?\d{11}|LT ?(?:\d{9}|\d{12})|LU ?\d{8}|LV ?\d{11}|MT ?\d{8}|NL ?\d{9}B\d{2}|PL ?\d{10}|PT ?\d{9}|RO ?\d{6,10}|SE ?\d{10}01|SI ?\d{8}|SK ?\d{10}|XI ?\d{9})\b`)},
		},
		EntityFRNIR: {
			{re: re(`\b[1-478] ?\d{2} ?\d{2} ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b`), validate: validNIR, numeric: true},
		},
		EntityDETaxID: {
			{re: re(`\b[1-9]\d ?\d{3} ?\d{3} ?\d{3}\b`), validate: validDETaxID, numeric: true,
				ctx: kw(`(?i)(?:steuer[- ]?id|steuer[- ]?identifikationsnummer|identifikationsnummer|\bidnr\b|\bst\.?-?idnr\b|\btax\s+id\b|\bTIN\b|steuernummer)`)},
		},
		EntityESDNI: {
			{re: re(`\b\d{8}[- ]?[A-Z]\b`), validate: validDNI, numeric: true},
		},
		EntityESNIE: {
			{re: re(`\b[XYZ][- ]?\d{7}[- ]?[A-Z]\b`), validate: validNIE},
		},
		EntityITFiscalCode: {
			{re: re(`\b[A-Z]{6}[\dLMNPQRSTUV]{2}[A-EHLMPRST][\dLMNPQRSTUV]{2}[A-Z][\dLMNPQRSTUV]{3}[A-Z]\b`), validate: validITFiscal},
		},
		EntityNLBSN: {
			{re: re(`\b\d{4}\.\d{2}\.\d{3}\b`), validate: validBSN, numeric: true},
			{re: re(`\b\d{9}\b`), validate: validBSN, numeric: true,
				ctx: kw(`(?i)\b(?:BSN|burgerservicenummer|sofi(?:nummer)?|citizen\s+service\s+number)\b`)},
		},
		EntityPLPESEL: {
			{re: re(`\b\d{11}\b`), validate: validPESEL, numeric: true},
		},

		// --- Canada ---
		EntityCASIN: {
			{re: re(`\b\d{3}[ -]\d{3}[ -]\d{3}\b`), validate: validSIN, numeric: true, notCtx: tfnKeyword},
			{re: re(`\b\d{9}\b`), validate: validSIN, numeric: true,
				ctx: kw(`\bSIN\b|(?i:\bsocial\s+insurance\b|\bNAS\b)`)},
		},
		EntityCAHealthCard: {
			{re: re(`\b(?:\d{4}[- ]?\d{3}[- ]?\d{3}(?:[- ]?[A-Z]{2})?|[A-Z]{4}[- ]?\d{4}[- ]?\d{4}|\d{9,10})\b`), numeric: true,
				ctx: kw(`(?i)(?:\bhealth\s+(?:card|number|no\.?|#)|\bOHIP\b|\bRAMQ\b|\bcarte\s+(?:sant[eé]|d'assurance\s+maladie)|\bPHN\b|\bpersonal\s+health\s+number|\bcare\s*card\b|\bHCN\b)`)},
		},
		EntityCAPostalCode: {
			{re: re(`\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d\b`)},
		},

		// --- Australia ---
		EntityAUTFN: {
			{re: re(`\b\d{3} \d{3} \d{2,3}\b`), validate: validTFN, numeric: true},
			{re: re(`\b\d{8,9}\b`), validate: validTFN, numeric: true, ctx: tfnKeyword},
		},
		EntityAUABN: {
			{re: re(`\b\d{2} ?\d{3} ?\d{3} ?\d{3}\b`), validate: validABN, numeric: true},
		},
		EntityAUMedicare: {
			{re: re(`\b[2-6]\d{3} \d{5} \d(?:[ /-]?\d)?\b`), validate: validAUMedicare, numeric: true},
			{re: re(`\b[2-6]\d{9,10}\b`), validate: validAUMedicare, numeric: true, ctx: kw(`(?i)\bmedicare\b`)},
		},

		// --- Financial ---
		EntitySWIFTBIC: {
			{re: re(`\b[A-Z]{4}[A-Z]{2}[A-Z2-9][A-NP-Z0-9](?:[A-Z0-9]{3})?\b`), validate: validBIC,
				ctx: kw(`(?i)\b(?:SWIFT|BIC)\b`)},
		},
		EntityCryptoWallet: {
			{re: re(`\b[13][1-9A-HJ-NP-Za-km-z]{25,34}\b`), validate: validBase58Check},
			{re: re(`\b(?:bc1|BC1)[02-9ac-hj-np-zAC-HJ-NP-Z]{11,71}\b`), validate: validBech32},
			{re: re(`\b0x[0-9a-fA-F]{40}\b`)},
		},

		// --- Health ---
		EntityUSNPI: {
			{re: re(`\b[12]\d{9}\b`), validate: validNPI, numeric: true,
				ctx: kw(`(?i)\b(?:NPI|national\s+provider|provider\s+(?:id|number|no))\b`)},
		},
		EntityUSDEA: {
			{re: re(`\b[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}\b`), validate: validDEA},
		},
		EntityMedicalRecord: {
			{re: re(`\b[A-Z]{0,3}-?\d{5,12}\b`), numeric: true,
				ctx: kw(`(?i)(?:\bMRN\b|\bmedical\s+record|\bmed\s*rec\b|\bpatient\s+(?:id|number|no\.?|#)|\bchart\s+(?:number|no\.?|#)|\bhospital\s+number)`)},
		},
		EntityHealthInsurance: {
			// Medicare Beneficiary Identifier: a fixed, distinctive 11-character layout.
			{re: re(`\b[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d-?[AC-HJKMNP-RT-Y]{2}\d{2}\b`)},
			{re: re(`\b(?:[A-Z]{1,4}\d{6,14}[A-Z]{0,2}|\d{6,14}|[A-Z0-9]{3,4}-\d{4,8}(?:-\d{2,4})?)\b`), numeric: true,
				ctx: kw(`(?i)(?:\bmember\s+(?:id|number|no\.?|#)|\bsubscriber\s+(?:id|number)|\bpolicy\s+(?:number|no\.?|#)|\binsurance\s+(?:id|number|no\.?|#)|\bhealth\s+(?:plan|insurance)\b|\bgroup\s+(?:number|no\.?)|\bmedicaid\b|\bmedicare\b|\bMBI\b|\binsured\s+id)`)},
		},

		// --- Network & credentials ---
		EntityIPv6:       {{find: findIPv6}},
		EntityMACAddress: {{re: re(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b|\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b`)}},
		EntityURLCredentials: {
			// Mask only the user:password part: https://[URL_CREDENTIALS]@host
			{re: re(`(?i)\b[a-z][a-z0-9+.\-]*://([^\s/:@"'<>]+:[^\s/@"'<>]+)@`), group: 1},
		},
		EntityConnectionString: {
			{re: re(`(?i)\b` + dbSchemes + `://[^\s:/@"'<>]+:[^\s@"'<>]+@[^\s"'<>]+`)},
			{re: re(`(?i)\b` + dbSchemes + `://[^\s"'<>]*[?&;](?:password|pwd)=[^\s&"'<>]+[^\s"'<>]*`)},
			{re: re(`(?i)\b(?:` + adoKeys + `\s*=[^;\n"']*;\s*)+(?:password|pwd)\s*=[^;\n"']+;?(?:\s*` + adoKeys + `\s*=[^;\n"']*;?)*`)},
			{re: re(`(?i)\b(?:password|pwd)\s*=[^;\n"']+;\s*(?:` + adoKeys + `\s*=[^;\n"']*;?\s*)+`)},
		},

		// --- Personal ---
		EntityDateOfBirth: {
			{re: re(`(?i)\b(?:\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)?\d{2}|(?:19|20)\d{2}[/.-]\d{1,2}[/.-]\d{1,2}|` + months + `\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}|\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?` + months + `\.?,?\s+(?:19|20)\d{2})\b`),
				ctx: kw(`(?i)(?:\bDOB\b|\bD\.O\.B\b|\bdate\s+of\s+birth\b|\bbirth\s*date\b|\bbirthday\b|\bborn\b|\bgeboren\b|\bfecha\s+de\s+nacimiento\b|\bdate\s+de\s+naissance\b|\bn[ée]e?\s+le\b)`)},
		},
		EntityStreetAddress: {{find: func(t string) [][2]int { return findStreetAddresses(t, streetRe) }}},
	}
}

// ibanLengths is the IBAN length per country (SWIFT IBAN registry).
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
	"BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
	"GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
	"IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
	"LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28,
	"NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

var ibanStartRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}`)

// findIBANs locates IBANs written compact or in groups ("DE89 3704 0044 …"):
// from each country prefix it consumes exactly the country's length of
// alphanumerics (single spaces allowed between groups) and checks mod-97.
func findIBANs(text string) [][2]int {
	var out [][2]int
	pos := 0
	for pos < len(text) {
		loc := ibanStartRe.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start := pos + loc[0]
		pos = start + 1
		n, ok := ibanLengths[text[start:start+2]]
		if !ok {
			continue
		}
		var sb strings.Builder
		i := start
		for i < len(text) && sb.Len() < n {
			c := text[i]
			switch {
			case isDigit(c) || (c >= 'A' && c <= 'Z'):
				sb.WriteByte(c)
				i++
			case c == ' ' && i+1 < len(text) && i > start && text[i-1] != ' ':
				i++
			default:
				i = len(text) + 1
			}
		}
		if i > len(text) || sb.Len() != n {
			continue
		}
		if i < len(text) && (isWordByte(text[i])) {
			continue
		}
		if !validIBAN(sb.String()) {
			continue
		}
		out = append(out, [2]int{start, i})
		pos = i
	}
	return out
}

var ipv6CandRe = regexp.MustCompile(`(?i)[0-9a-f]*(?::[0-9a-f]*){2,8}(?:\.\d{1,3}){0,3}`)

// findIPv6 finds IPv6 addresses validated by net.ParseIP.
func findIPv6(text string) [][2]int {
	var out [][2]int
	for _, loc := range ipv6CandRe.FindAllStringIndex(text, -1) {
		s, e := loc[0], loc[1]
		for e-s > 2 && text[e-1] == ':' && text[e-2] != ':' {
			e--
		}
		v := text[s:e]
		if len(v) < 6 || !strings.Contains(v, ":") {
			continue
		}
		if s > 0 {
			if p := text[s-1]; isWordByte(p) || p == ':' || p == '.' {
				continue
			}
		}
		if e < len(text) && isWordByte(text[e]) {
			continue
		}
		if net.ParseIP(v) == nil {
			continue
		}
		out = append(out, [2]int{s, e})
	}
	return out
}

// Street suffixes that are also common English words ("20 People Drive growth").
var ambiguousStreetSuffix = map[string]bool{"Drive": true, "Dr": true, "Way": true, "Court": true, "Ct": true, "Place": true,
	"Pl": true, "Circle": true, "Cir": true, "Square": true, "Sq": true, "Trail": true, "Trl": true, "Close": true,
	"Crescent": true, "Plaza": true, "Alley": true, "Ter": true, "St": true}

// Words that, right before the number, mark it as a quantity or a year rather
// than a house number ("team of 20 ...", "in 1999 ...").
var streetStopWords = map[string]bool{"of": true, "than": true, "about": true, "over": true, "under": true, "top": true,
	"nearly": true, "around": true, "almost": true, "approximately": true, "in": true, "with": true, "these": true,
	"those": true, "our": true, "your": true, "their": true, "its": true, "all": true, "only": true, "just": true,
	"another": true, "other": true, "every": true, "first": true, "last": true, "since": true, "until": true, "by": true}

var (
	streetTrailRe = regexp.MustCompile(`^(?:,\s*[A-Z]|,?\s+\d{5}\b|,?\s+[A-Z]{2}\s+\d{5}\b)`)
	streetCueRe   = regexp.MustCompile(`(?i)\b(?:at|address|addr|located|lives?|living|resides?|residing|ship(?:ped)?\s+to|deliver(?:ed)?\s+to|mail(?:ed)?\s+to|send\s+to|moved\s+to|office|home)\b[^\n]{0,12}$`)
	lastWordRe    = regexp.MustCompile(`([A-Za-z]+)\W*$`)
)

// findStreetAddresses filters street-address candidates: no quantity / year
// stop word before the number, and suffixes that are ordinary words (Drive,
// Way, Place, ...) need an address cue (a unit, ", City", a ZIP code, or "at",
// "address", "ship to" ... just before).
func findStreetAddresses(text string, re *regexp.Regexp) [][2]int {
	var out [][2]int
	for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
		s, e := loc[0], loc[1]
		before := text[max(0, s-40):s]
		if m := lastWordRe.FindStringSubmatch(before); m != nil && streetStopWords[strings.ToLower(m[1])] {
			continue
		}
		suffix := text[loc[2]:loc[3]]
		hasUnit := loc[4] >= 0 && loc[5] > loc[4]
		if ambiguousStreetSuffix[suffix] && !hasUnit && !streetTrailRe.MatchString(text[e:]) && !streetCueRe.MatchString(before) {
			continue
		}
		out = append(out, [2]int{s, e})
	}
	return out
}
