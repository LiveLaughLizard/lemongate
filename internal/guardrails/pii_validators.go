package guardrails

import (
	"crypto/sha256"
	"math/big"
	"strings"
)

// Checksum and structure validators for the regional PII library. Each takes
// the matched text (possibly with spaces, dashes or dots) and reports whether it
// is a plausible identifier of that type.

// digitsOf strips separators and returns the digits as ints; ok is false when
// the length is not n.
func digitsOf(s string, n int) ([]int, bool) {
	d := onlyDigits(s)
	if len(d) != n {
		return nil, false
	}
	out := make([]int, n)
	for i := range d {
		out[i] = int(d[i] - '0')
	}
	return out, true
}

// validITIN: 9XX-YY-ZZZZ where YY is 50–65, 70–88, 90–92 or 94–99.
func validITIN(s string) bool {
	d, ok := digitsOf(s, 9)
	if !ok || d[0] != 9 {
		return false
	}
	g := d[3]*10 + d[4]
	return (g >= 50 && g <= 65) || (g >= 70 && g <= 88) || (g >= 90 && g <= 92) || (g >= 94 && g <= 99)
}

// validABA checks an ABA routing transit number: Federal Reserve prefix and
// the 3-7-1 weighted checksum.
func validABA(s string) bool {
	d, ok := digitsOf(s, 9)
	if !ok || repeated(onlyDigits(s)) {
		return false
	}
	p := d[0]*10 + d[1]
	if !((p <= 12) || (p >= 21 && p <= 32) || (p >= 61 && p <= 72) || p == 80) {
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}

// einInvalidPrefix lists EIN campus prefixes the IRS never assigns.
var einInvalidPrefix = map[int]bool{0: true, 7: true, 8: true, 9: true, 17: true, 18: true, 19: true, 28: true, 29: true,
	49: true, 69: true, 70: true, 78: true, 79: true, 89: true, 96: true, 97: true}

// validEIN checks the length and the two-digit prefix of an employer identification number.
func validEIN(s string) bool {
	d, ok := digitsOf(s, 9)
	if !ok || repeated(onlyDigits(s)) {
		return false
	}
	return !einInvalidPrefix[d[0]*10+d[1]]
}

// validNINO rejects National Insurance prefixes that are never issued.
func validNINO(s string) bool {
	c := strings.ReplaceAll(s, " ", "")
	if len(c) != 9 {
		return false
	}
	switch c[:2] {
	case "BG", "GB", "NK", "KN", "TN", "NT", "ZZ":
		return false
	}
	return true
}

// validNHS checks the NHS number modulus-11 check digit.
func validNHS(s string) bool {
	d, ok := digitsOf(s, 10)
	if !ok || repeated(onlyDigits(s)) {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += d[i] * (10 - i)
	}
	check := 11 - sum%11
	if check == 11 {
		check = 0
	}
	return check != 10 && check == d[9]
}

// validNIR checks a French social security number: month range and the
// 97-complement control key (Corsican departments 2A/2B map to 19/18).
func validNIR(s string) bool {
	c := strings.ReplaceAll(s, " ", "")
	if len(c) != 15 {
		return false
	}
	month := int(c[3]-'0')*10 + int(c[4]-'0')
	if c[3] > '9' || c[4] > '9' || !((month >= 1 && month <= 12) || (month >= 20 && month <= 42) || (month >= 50 && month <= 99)) {
		return false
	}
	// Corsica: 2A and 2B are computed as 19 and 18 (i.e. 20 minus 1 / 2 million).
	body := c[:13]
	switch body[5:7] {
	case "2A":
		body = body[:5] + "19" + body[7:]
	case "2B":
		body = body[:5] + "18" + body[7:]
	}
	var n int64
	for i := 0; i < len(body); i++ {
		if !isDigit(body[i]) {
			return false
		}
		n = n*10 + int64(body[i]-'0')
	}
	if !isDigit(c[13]) || !isDigit(c[14]) {
		return false
	}
	key := int64(c[13]-'0')*10 + int64(c[14]-'0')
	return key == 97-n%97
}

// validDETaxID checks a German Steuer-IdNr: digit-frequency rule (exactly one
// digit repeated two or three times in the first ten) and the ISO 7064
// MOD 11,10 check digit.
func validDETaxID(s string) bool {
	d, ok := digitsOf(s, 11)
	if !ok || d[0] == 0 {
		return false
	}
	var freq [10]int
	for _, x := range d[:10] {
		freq[x]++
	}
	multi := 0
	for _, f := range freq {
		switch {
		case f > 3:
			return false
		case f >= 2:
			multi++
		}
	}
	if multi != 1 {
		return false
	}
	product := 10
	for _, x := range d[:10] {
		sum := (x + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == d[10]
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// validDNI checks the Spanish DNI control letter (number mod 23).
func validDNI(s string) bool {
	c := strings.NewReplacer(" ", "", "-", "").Replace(s)
	if len(c) != 9 {
		return false
	}
	n := 0
	for i := 0; i < 8; i++ {
		if !isDigit(c[i]) {
			return false
		}
		n = n*10 + int(c[i]-'0')
	}
	return dniLetters[n%23] == c[8]
}

// validNIE checks a Spanish foreigner id: X/Y/Z map to 0/1/2, then the DNI rule.
func validNIE(s string) bool {
	c := strings.NewReplacer(" ", "", "-", "").Replace(s)
	if len(c) != 9 {
		return false
	}
	p := strings.IndexByte("XYZ", c[0])
	if p < 0 {
		return false
	}
	return validDNI(string(rune('0'+p)) + c[1:])
}

// Italian fiscal code check-character tables (odd = 1st, 3rd, ... positions).
var itOdd = [36]int{
	// 0-9
	1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
	// A-Z
	1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23,
}

// validITFiscal checks the 16th (control) character of an Italian codice fiscale.
func validITFiscal(s string) bool {
	if len(s) != 16 {
		return false
	}
	sum := 0
	for i := 0; i < 15; i++ {
		c := s[i]
		var idx, even int
		switch {
		case isDigit(c):
			idx, even = int(c-'0'), int(c-'0')
		case c >= 'A' && c <= 'Z':
			idx, even = 10+int(c-'A'), int(c-'A')
		default:
			return false
		}
		if i%2 == 0 {
			sum += itOdd[idx]
		} else {
			sum += even
		}
	}
	return s[15] == byte('A'+sum%26)
}

// validBSN applies the Dutch "11-proof" to a burgerservicenummer.
func validBSN(s string) bool {
	d, ok := digitsOf(s, 9)
	if !ok || repeated(onlyDigits(s)) {
		return false
	}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += d[i] * (9 - i)
	}
	sum -= d[8]
	return sum%11 == 0
}

// validPESEL checks the encoded birth date and the weighted checksum of a Polish PESEL.
func validPESEL(s string) bool {
	d, ok := digitsOf(s, 11)
	if !ok || repeated(onlyDigits(s)) {
		return false
	}
	month := d[2]*10 + d[3]
	if month > 80 {
		month -= 80
	} else if month > 60 {
		month -= 60
	} else if month > 40 {
		month -= 40
	} else if month > 20 {
		month -= 20
	}
	day := d[4]*10 + d[5]
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	w := [10]int{1, 3, 7, 9, 1, 3, 7, 9, 1, 3}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += d[i] * w[i]
	}
	return (10-sum%10)%10 == d[10]
}

// validSIN checks a Canadian social insurance number (Luhn; 8 is never issued,
// 0 is reserved for test / fictitious numbers and still masked).
func validSIN(s string) bool {
	d := onlyDigits(s)
	if len(d) != 9 || d[0] == '8' || repeated(d) {
		return false
	}
	return Luhn(d)
}

// validTFN checks an Australian tax file number (8 or 9 digits, weighted mod 11).
func validTFN(s string) bool {
	d := onlyDigits(s)
	var w []int
	switch len(d) {
	case 9:
		w = []int{1, 4, 3, 7, 5, 8, 6, 9, 10}
	case 8:
		w = []int{10, 7, 8, 4, 6, 3, 5, 1}
	default:
		return false
	}
	if repeated(d) {
		return false
	}
	sum := 0
	for i := range d {
		sum += int(d[i]-'0') * w[i]
	}
	return sum%11 == 0
}

// validABN checks an Australian business number (mod 89).
func validABN(s string) bool {
	d, ok := digitsOf(s, 11)
	if !ok || d[0] == 0 {
		return false
	}
	w := [11]int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}
	sum := (d[0] - 1) * w[0]
	for i := 1; i < 11; i++ {
		sum += d[i] * w[i]
	}
	return sum%89 == 0
}

// validAUMedicare checks a Medicare card number: first digit 2–6, weighted
// check digit in position 9, then the issue number (and optional IRN).
func validAUMedicare(s string) bool {
	d := onlyDigits(s)
	if len(d) != 10 && len(d) != 11 {
		return false
	}
	if d[0] < '2' || d[0] > '6' {
		return false
	}
	w := [8]int{1, 3, 7, 9, 1, 3, 7, 9}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(d[i]-'0') * w[i]
	}
	return sum%10 == int(d[8]-'0')
}

// isoCountries lists ISO 3166-1 alpha-2 codes (plus XK) for BIC validation.
var isoCountries = func() map[string]bool {
	const codes = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
		"CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
		"GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
		"KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
		"MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
		"SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
		"UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW"
	m := map[string]bool{}
	for _, c := range strings.Fields(codes) {
		m[c] = true
	}
	return m
}()

// validBIC checks the length and country code of a SWIFT / BIC code.
func validBIC(s string) bool {
	if len(s) != 8 && len(s) != 11 {
		return false
	}
	return isoCountries[s[4:6]]
}

// validIBAN checks the length per country and the ISO 13616 mod-97 remainder.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if n, ok := ibanLengths[s[:2]]; !ok || n != len(s) {
		return false
	}
	r := s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case isDigit(c):
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// validBase58Check decodes a legacy Bitcoin address and verifies its double-SHA-256 checksum.
func validBase58Check(s string) bool {
	n := new(big.Int)
	b58 := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(base58Alphabet, s[i])
		if v < 0 {
			return false
		}
		n.Mul(n, b58)
		n.Add(n, big.NewInt(int64(v)))
	}
	raw := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	raw = append(make([]byte, zeros), raw...)
	if len(raw) != 25 {
		return false
	}
	h1 := sha256.Sum256(raw[:21])
	h2 := sha256.Sum256(h1[:])
	return string(h2[:4]) == string(raw[21:])
}

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// validBech32 verifies a segwit address checksum (bech32 or bech32m, hrp "bc").
func validBech32(s string) bool {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return false // mixed case is invalid
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || len(s)-pos-1 < 6 || len(s) > 90 {
		return false
	}
	hrp, data := s[:pos], s[pos+1:]
	var vals []int
	for i := 0; i < len(hrp); i++ {
		vals = append(vals, int(hrp[i])>>5)
	}
	vals = append(vals, 0)
	for i := 0; i < len(hrp); i++ {
		vals = append(vals, int(hrp[i])&31)
	}
	for i := 0; i < len(data); i++ {
		v := strings.IndexByte(bech32Charset, data[i])
		if v < 0 {
			return false
		}
		vals = append(vals, v)
	}
	pm := bech32Polymod(vals)
	return pm == 1 || pm == 0x2bc830a3
}

// validNPI checks a US National Provider Identifier: Luhn over "80840" + the number.
func validNPI(s string) bool {
	d := onlyDigits(s)
	return len(d) == 10 && Luhn("80840"+d)
}

// validDEA checks a DEA registration number: (d1+d3+d5) + 2*(d2+d4+d6) ends in d7.
func validDEA(s string) bool {
	if len(s) != 9 {
		return false
	}
	d, ok := digitsOf(s[2:], 7)
	if !ok {
		return false
	}
	sum := d[0] + d[2] + d[4] + 2*(d[1]+d[3]+d[5])
	return sum%10 == d[6]
}
