package guardrails

import (
	"slices"
	"testing"
)

func TestValidators(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		ok   []string
		bad  []string
	}{
		{"ITIN", validITIN, []string{"912-70-1234", "900 50 0000", "999949999"}, []string{"912-66-1234", "912-89-1234", "812-70-1234", "912-93-1234"}},
		{"ABA", validABA, []string{"021000021", "011000015", "121000358"}, []string{"021000022", "000000000", "991000021"}},
		{"EIN", validEIN, []string{"12-3456789", "953456789"}, []string{"07-1234567", "00-1234567", "11-111111", "111111111"}},
		{"NINO", validNINO, []string{"AB 12 34 56 C", "AB123456C"}, []string{"BG123456A", "GB 12 34 56 A", "AB12345C"}},
		{"NHS", validNHS, []string{"943 476 5919", "9434765919"}, []string{"943 476 5918", "0000000000", "943476591"}},
		{"NIR", validNIR, []string{"185057800608491", "2 69 02 99 341 732 85", "185052A00608435"}, []string{"185057800608492", "185137800608491", "18505780060849"}},
		{"DETaxID", validDETaxID, []string{"86095742719", "86 095 742 719"}, []string{"86095742718", "01234567899", "11111111111", "12345678901"}},
		{"DNI", validDNI, []string{"12345678Z", "12345678-Z", "00000000T"}, []string{"12345678A", "1234567Z"}},
		{"NIE", validNIE, []string{"X1234567L", "Y-1234567-X", "Z1234567R"}, []string{"X1234567A", "A1234567L"}},
		{"ITFiscal", validITFiscal, []string{"RSSMRA85T10A562S"}, []string{"RSSMRA85T10A562T", "RSSMRA85T10A562"}},
		{"BSN", validBSN, []string{"111222333", "1234.56.782"}, []string{"111222334", "000000000", "12345678"}},
		{"PESEL", validPESEL, []string{"44051401359", "02270803624"}, []string{"44051401358", "44151401359", "44053201359"}},
		{"SIN", validSIN, []string{"046 454 286", "046454286"}, []string{"046 454 287", "846454286", "000000000"}},
		{"TFN", validTFN, []string{"123 456 782", "123456782", "37118629"}, []string{"123456789", "111111111", "1234567"}},
		{"ABN", validABN, []string{"51 824 753 556", "51824753556"}, []string{"51824753557", "01824753556"}},
		{"AUMedicare", validAUMedicare, []string{"2123 45670 1", "21234567011"}, []string{"2123456791", "7123456701", "212345670"}},
		{"BIC", validBIC, []string{"DEUTDEFF", "DEUTDEFF500", "BOFAUS3N"}, []string{"DEUTXXFF", "DEUTDEFF50", "DEUT"}},
		{"IBAN", validIBAN, []string{"DE89370400440532013000", "GB82WEST12345698765432", "FR1420041010050500013M02606", "NL91ABNA0417164300"},
			[]string{"DE89370400440532013001", "DE8937040044053201300", "XX89370400440532013000"}},
		{"Base58Check", validBase58Check, []string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
			[]string{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "1111111111111111111114oLvT3", "10IOl"}},
		{"Bech32", validBech32, []string{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"},
			[]string{"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdp", "bc1QAR0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "bc1qbbbbbb"}},
		{"NPI", validNPI, []string{"1234567893", "1245319599"}, []string{"1234567890", "123456789"}},
		{"DEA", validDEA, []string{"AB1234563", "F91234563"}, []string{"AB1234564", "AB123456"}},
		{"SSN", validSSN, []string{"123-45-6789"}, []string{"000-12-3456", "666-12-3456", "923-45-6789", "123-00-6789", "123-45-0000"}},
		{"Card", validCard, []string{"4111 1111 1111 1111", "378282246310005"}, []string{"4111111111111112", "0000000000000000"}},
	}
	for _, c := range cases {
		for _, v := range c.ok {
			if !c.fn(v) {
				t.Errorf("%s(%q) = false, want true", c.name, v)
			}
		}
		for _, v := range c.bad {
			if c.fn(v) {
				t.Errorf("%s(%q) = true, want false", c.name, v)
			}
		}
	}
}

func TestEntityTable(t *testing.T) {
	ids := AllEntityIDs()
	if len(ids) != len(Entities) {
		t.Fatal("AllEntityIDs length mismatch")
	}
	groups := EntityGroups()
	seen := map[string]bool{}
	for _, e := range Entities {
		if seen[e.ID] {
			t.Errorf("duplicate entity %s", e.ID)
		}
		seen[e.ID] = true
		if !slices.Contains(groups, e.Group) {
			t.Errorf("entity %s has unknown group %q", e.ID, e.Group)
		}
		if len(detectors[e.ID]) == 0 {
			t.Errorf("entity %s has no detectors", e.ID)
		}
		if !slices.Contains(detectionOrder, e.ID) {
			t.Errorf("entity %s missing from detectionOrder", e.ID)
		}
		if e.Label == "" || e.Mask == "" {
			t.Errorf("entity %s lacks label or mask", e.ID)
		}
	}
	if len(detectionOrder) != len(Entities) {
		t.Errorf("detectionOrder has %d ids, Entities %d", len(detectionOrder), len(Entities))
	}
	// Display order of groups: entities never go back to an earlier group.
	last := -1
	for _, e := range Entities {
		gi := slices.Index(groups, e.Group)
		if gi < last {
			t.Errorf("entity %s (%s) out of group display order", e.ID, e.Group)
		}
		last = gi
	}
	// The contract ids.
	for _, id := range []string{"email", "phone", "ssn", "credit_card", "ipv4", "secret",
		"us_itin", "us_passport", "us_drivers_license", "us_bank_routing", "us_ein",
		"uk_nino", "uk_nhs", "uk_postcode", "uk_sort_code",
		"iban", "eu_vat", "fr_nir", "de_tax_id", "es_dni", "es_nie", "it_fiscal_code", "nl_bsn", "pl_pesel",
		"ca_sin", "ca_health_card", "ca_postal_code", "au_tfn", "au_abn", "au_medicare",
		"swift_bic", "crypto_wallet", "us_npi", "us_dea", "medical_record_number", "health_insurance_id",
		"ipv6", "mac_address", "url_credentials", "connection_string", "date_of_birth", "street_address"} {
		if !seen[id] {
			t.Errorf("missing entity id %s", id)
		}
	}
}

func TestMaskRegionalPII(t *testing.T) {
	cases := []struct {
		entity, in, want string
	}{
		{EntityUSITIN, "ITIN 912-70-1234 on file", "ITIN [US_ITIN] on file"},
		{EntityUSITIN, "my ITIN is 912701234", "my ITIN is [US_ITIN]"},
		{EntityUSPassport, "passport no. C03005988", "passport no. [US_PASSPORT]"},
		{EntityUSDriversLicense, "driver's license D123-456-78-901-2", "driver's license [US_DRIVERS_LICENSE]"},
		{EntityUSBankRouting, "routing number 021000021", "routing number [US_BANK_ROUTING]"},
		{EntityUSEIN, "our EIN is 12-3456789.", "our EIN is [US_EIN]."},
		{EntityUKNINO, "NI number AB 12 34 56 C", "NI number [UK_NINO]"},
		{EntityUKNHS, "NHS number 943 476 5919", "NHS number [UK_NHS]"},
		{EntityUKPostcode, "London SW1A 1AA, UK", "London [UK_POSTCODE], UK"},
		{EntityUKSortCode, "sort code 20-00-00", "sort code [UK_SORT_CODE]"},
		{EntityIBAN, "IBAN DE89 3704 0044 0532 0130 00 please", "IBAN [IBAN] please"},
		{EntityIBAN, "pay GB82WEST12345698765432", "pay [IBAN]"},
		{EntityEUVAT, "VAT DE123456789", "VAT [EU_VAT]"},
		{EntityFRNIR, "NIR 1 85 05 78 006 084 91", "NIR [FR_NIR]"},
		{EntityDETaxID, "Steuer-ID 86095742719", "Steuer-ID [DE_TAX_ID]"},
		{EntityESDNI, "DNI 12345678Z", "DNI [ES_DNI]"},
		{EntityESNIE, "NIE X1234567L", "NIE [ES_NIE]"},
		{EntityITFiscalCode, "CF RSSMRA85T10A562S", "CF [IT_FISCAL_CODE]"},
		{EntityNLBSN, "BSN 111222333", "BSN [NL_BSN]"},
		{EntityPLPESEL, "PESEL 44051401359", "PESEL [PL_PESEL]"},
		{EntityCASIN, "SIN 046 454 286", "SIN [CA_SIN]"},
		{EntityCAHealthCard, "OHIP health card 1234-567-890-AB", "OHIP health card [CA_HEALTH_CARD]"},
		{EntityCAPostalCode, "Ottawa ON K1A 0B1", "Ottawa ON [CA_POSTAL_CODE]"},
		{EntityAUTFN, "TFN 123 456 782", "TFN [AU_TFN]"},
		{EntityAUABN, "ABN 51 824 753 556", "ABN [AU_ABN]"},
		{EntityAUMedicare, "Medicare 2123 45670 1", "Medicare [AU_MEDICARE]"},
		{EntitySWIFTBIC, "SWIFT code DEUTDEFF500", "SWIFT code [SWIFT_BIC]"},
		{EntityCryptoWallet, "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now", "send to [CRYPTO_WALLET] now"},
		{EntityCryptoWallet, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "[CRYPTO_WALLET]"},
		{EntityCryptoWallet, "eth 0x52908400098527886E0F7030069857D2E4169EE7", "eth [CRYPTO_WALLET]"},
		{EntityUSNPI, "NPI 1234567893", "NPI [US_NPI]"},
		{EntityUSDEA, "DEA AB1234563", "DEA [US_DEA]"},
		{EntityMedicalRecord, "MRN 00123456", "MRN [MEDICAL_RECORD_NUMBER]"},
		{EntityHealthInsurance, "member ID XYZ123456789", "member ID [HEALTH_INSURANCE_ID]"},
		{EntityHealthInsurance, "MBI 1EG4-TE5-MK73", "MBI [HEALTH_INSURANCE_ID]"},
		{EntityIPv6, "host 2001:db8::8a2e:370:7334 up", "host [IP_ADDRESS] up"},
		{EntityMACAddress, "mac 00:1A:2B:3C:4D:5E", "mac [MAC_ADDRESS]"},
		{EntityURLCredentials, "https://admin:hunter2@example.com/x", "https://[URL_CREDENTIALS]@example.com/x"},
		{EntityConnectionString, "dsn postgres://app:s3cret@db.internal:5432/main ok", "dsn [CONNECTION_STRING] ok"},
		{EntityConnectionString, "Server=db1;Database=main;User Id=sa;Password=Pa55word;", "[CONNECTION_STRING]"},
		{EntityDateOfBirth, "DOB: 04/12/1985", "DOB: [DATE_OF_BIRTH]"},
		{EntityDateOfBirth, "born on March 3, 1990", "born on [DATE_OF_BIRTH]"},
		{EntityStreetAddress, "ship to 742 Evergreen Terrace, Springfield", "ship to [STREET_ADDRESS], Springfield"},
		{EntityStreetAddress, "1600 Pennsylvania Avenue NW", "[STREET_ADDRESS] NW"},
		{EntityStreetAddress, "she lives at 12 Birch Drive", "she lives at [STREET_ADDRESS]"},
		{EntityStreetAddress, "4 Privet Drive, Little Whinging", "[STREET_ADDRESS], Little Whinging"},
		{EntityStreetAddress, "350 Fifth Avenue, Suite 3400", "[STREET_ADDRESS]"},
	}
	for _, c := range cases {
		got, counts := MaskPII(c.in, nil)
		if got != c.want {
			t.Errorf("%s: MaskPII(%q) = %q, want %q (%v)", c.entity, c.in, got, c.want, counts)
			continue
		}
		if counts[c.entity] == 0 {
			t.Errorf("%s: no count for %q (%v)", c.entity, c.in, counts)
		}
	}
}

func TestContextEntitiesNeedKeyword(t *testing.T) {
	for _, in := range []string{
		"invoice 021000021 paid",                 // ABA without "routing"
		"ticket 9434765919",                      // NHS without "NHS"
		"ref 1234567893",                         // NPI without "NPI"
		"code DEUTDEFF500 shipped",               // BIC without SWIFT/BIC
		"version 04/12/1985",                     // date without DOB keyword
		"order C03005988",                        // passport shape without "passport"
		"batch 86095742719",                      // DE tax id without keyword
		"our team of 20 People Drive growth",     // "Drive" as a verb
		"In 1999 Microsoft Way was the plan",     // year, not a house number
		"amounts 11 222 333 444 were reconciled", // space-grouped number
		"Meeting on 2024-10-15 at 14:30:00 UTC, PR #4521",
		"uuid 123e4567-e89b-12d3-a456-426614174000",
	} {
		if got, counts := MaskPII(in, nil); got != in {
			t.Errorf("MaskPII(%q) = %q (%v), want unchanged", in, got, counts)
		}
	}
	// Each value only sees its own keyword.
	got, _ := MaskPII("passport 123456789, routing 021000021", nil)
	if got != "passport [US_PASSPORT], routing [US_BANK_ROUTING]" {
		t.Errorf("got %q", got)
	}
}

// businessProse is ordinary text that must produce no PII, injection or code hits.
const businessProse = `Quarterly update: revenue grew 12% to $4.2 million in Q3 2024, driven by 1,250 new
customers across 14 regions. The board approved the 2025 budget on 15 October and asked the
team to ignore minor rounding differences in the appendix. Please review the updated sales
playbook before Monday's 10:30 meeting in Room 4B; version 2.3.1 adds guidance for renewals.
Our support queue closed 9,876 tickets (median response 3h 20m) and the NPS rose from 41 to 47.
Next steps: finalize the hiring plan for 6 engineers, migrate the reporting dashboards, and
update the system documentation for the new onboarding flow. Contact the finance team with
questions about invoice INV-20240917 or purchase order PO 4471. Thanks, and well done everyone!
Previous instructions from the travel desk still apply: book economy for flights under 6 hours.
We will drop the legacy table view from the dashboard next sprint and delete stale drafts from the
shared folder. Execute the plan, evaluate results (eval scores up 8%), and select the best option.`

func TestBusinessProseHasNoFalsePositives(t *testing.T) {
	if got, counts := MaskPII(businessProse, nil); got != businessProse {
		t.Errorf("PII false positives: %v\n%s", counts, got)
	}
	if score, sig := InjectionScore(businessProse); len(sig) > 0 {
		t.Errorf("injection false positives: %v (%.2f)", sig, score)
	}
	if langs, pats := DetectCode(businessProse, nil); len(langs)+len(pats) > 0 {
		t.Errorf("code false positives: %v %v", langs, pats)
	}
}

func TestPIIValidateEntities(t *testing.T) {
	g := Guardrail{Name: "eu", Kind: KindPII, Mode: ModePre, Action: ActionMask,
		Config: Config{Entities: []string{EntityIBAN, EntityESDNI, " iban "}}}
	if err := Validate(&g); err != nil {
		t.Fatal(err)
	}
	if len(g.Config.Entities) != 2 {
		t.Fatalf("entities not cleaned: %v", g.Config.Entities)
	}
	g.Config.Entities = []string{"us_social"}
	if err := Validate(&g); err == nil {
		t.Fatal("unknown entity accepted")
	}
}
