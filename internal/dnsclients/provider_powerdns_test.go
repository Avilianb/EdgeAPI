package dnsclients

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/TeaOSLab/EdgeAPI/internal/dnsclients/dnstypes"
	"github.com/TeaOSLab/EdgeAPI/internal/dnsclients/powerdns"
	"github.com/iwind/TeaGo/maps"
)

type powerDNSTestAPI struct {
	lock        sync.Mutex
	zone        powerdns.Zone
	notifyCount int
}

func newPowerDNSTestAPI() *powerDNSTestAPI {
	return &powerDNSTestAPI{
		zone: powerdns.Zone{
			ID:   "ge.netr0.me.",
			Name: "ge.netr0.me.",
			Kind: "Master",
			RRSets: []powerdns.RRSet{
				{
					Name: "ge.netr0.me.",
					Type: "SOA",
					TTL:  300,
					Records: []powerdns.Record{
						{Content: "ns2.ge.netr0.me. hostmaster.netr0.me. 2026072601 300 60 1209600 300"},
					},
				},
				{
					Name: "ge.netr0.me.",
					Type: "NS",
					TTL:  300,
					Records: []powerdns.Record{
						{Content: "ns1.ge.netr0.me."},
						{Content: "ns2.ge.netr0.me."},
						{Content: "ns3.ge.netr0.me."},
					},
				},
			},
		},
	}
}

func (this *powerDNSTestAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Header.Get("X-API-Key") != "secret" {
		http.Error(writer, `{"error":"invalid api key"}`, http.StatusUnauthorized)
		return
	}

	const zonesPath = "/api/v1/servers/localhost/zones"
	switch {
	case request.Method == http.MethodGet && request.URL.Path == zonesPath:
		this.lock.Lock()
		zone := this.zone
		this.lock.Unlock()
		_ = json.NewEncoder(writer).Encode([]powerdns.Zone{zone})
	case request.Method == http.MethodGet && request.URL.Path == zonesPath+"/ge.netr0.me.":
		this.lock.Lock()
		zone := this.zone
		this.lock.Unlock()
		_ = json.NewEncoder(writer).Encode(zone)
	case request.Method == http.MethodPatch && request.URL.Path == zonesPath+"/ge.netr0.me.":
		patch := powerdns.PatchZoneRequest{}
		if err := json.NewDecoder(request.Body).Decode(&patch); err != nil {
			http.Error(writer, `{"error":"invalid patch"}`, http.StatusBadRequest)
			return
		}
		this.lock.Lock()
		for _, changedRRSet := range patch.RRSets {
			index := -1
			for rrsetIndex, existingRRSet := range this.zone.RRSets {
				if strings.EqualFold(existingRRSet.Name, changedRRSet.Name) && existingRRSet.Type == changedRRSet.Type {
					index = rrsetIndex
					break
				}
			}
			switch changedRRSet.ChangeType {
			case "DELETE":
				if index >= 0 {
					this.zone.RRSets = append(this.zone.RRSets[:index], this.zone.RRSets[index+1:]...)
				}
			case "REPLACE":
				changedRRSet.ChangeType = ""
				if index >= 0 {
					this.zone.RRSets[index] = changedRRSet
				} else {
					this.zone.RRSets = append(this.zone.RRSets, changedRRSet)
				}
				if changedRRSet.Type == "SOA" && len(changedRRSet.Records) == 1 {
					fields := strings.Fields(changedRRSet.Records[0].Content)
					if len(fields) == 7 {
						serial, _ := strconv.ParseUint(fields[2], 10, 32)
						this.zone.Serial = uint32(serial)
					}
				}
			default:
				this.lock.Unlock()
				http.Error(writer, `{"error":"unsupported change type"}`, http.StatusBadRequest)
				return
			}
		}
		this.lock.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	case request.Method == http.MethodPut && request.URL.Path == zonesPath+"/ge.netr0.me./notify":
		this.lock.Lock()
		this.notifyCount++
		this.lock.Unlock()
		_, _ = writer.Write([]byte(`{"result":"Notification queued"}`))
	default:
		http.NotFound(writer, request)
	}
}

func (this *powerDNSTestAPI) serialAndNotifyCount() (uint32, int) {
	this.lock.Lock()
	defer this.lock.Unlock()
	return this.zone.Serial, this.notifyCount
}

func (this *powerDNSTestAPI) findRRSet(name string, recordType string) *powerdns.RRSet {
	this.lock.Lock()
	defer this.lock.Unlock()
	for _, rrset := range this.zone.RRSets {
		if strings.EqualFold(rrset.Name, name) && rrset.Type == recordType {
			result := rrset
			return &result
		}
	}
	return nil
}

func newPowerDNSTestProvider(t *testing.T, apiURL string) *PowerDNSProvider {
	t.Helper()
	provider := &PowerDNSProvider{}
	err := provider.Auth(maps.Map{
		"endpoint":   apiURL,
		"apiKey":     "secret",
		"serverId":   "localhost",
		"healthPort": 443,
		"routes":     "country:US|美国\ncountry:JP|日本\nregion:CA|加利福尼亚",
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestPowerDNSProviderAddressLifecycle(t *testing.T) {
	testAPI := newPowerDNSTestAPI()
	server := httptest.NewServer(testAPI)
	defer server.Close()

	provider := newPowerDNSTestProvider(t, server.URL)
	inputRecords := []*dnstypes.Record{
		{Name: "cdn", Type: dnstypes.RecordTypeA, Value: "8.138.241.69", Route: PowerDNSClosestRoute, TTL: 60},
		{Name: "cdn", Type: dnstypes.RecordTypeA, Value: "47.108.77.161", Route: PowerDNSClosestRoute, TTL: 60},
		{Name: "cdn", Type: dnstypes.RecordTypeA, Value: "218.244.152.85", Route: "country:CN", TTL: 60},
	}
	for _, record := range inputRecords {
		if err := provider.AddRecord("ge.netr0.me", record); err != nil {
			t.Fatal(err)
		}
		if len(record.Id) == 0 {
			t.Fatal("expected generated record ID")
		}
	}

	records, err := provider.QueryRecords("ge.netr0.me", "cdn", dnstypes.RecordTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 logical records, got %d", len(records))
	}

	luaRRSet := testAPI.findRRSet("cdn.ge.netr0.me.", "LUA")
	if luaRRSet == nil {
		t.Fatal("expected managed LUA RRset")
	}
	if len(luaRRSet.Records) != 1 || len(luaRRSet.Comments) != 3 {
		t.Fatalf("unexpected LUA RRset: %#v", luaRRSet)
	}
	luaContent := luaRRSet.Records[0].Content
	for _, expected := range []string{"ifportup(443", "selector='pickclosest'", "country('CN')"} {
		if !strings.Contains(luaContent, expected) {
			t.Fatalf("expected LUA content to contain %q: %s", expected, luaContent)
		}
	}

	if err = provider.DeleteRecord("ge.netr0.me", records[0]); err != nil {
		t.Fatal(err)
	}
	records, err = provider.QueryRecords("ge.netr0.me", "cdn", dnstypes.RecordTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 logical records after delete, got %d", len(records))
	}
	luaRRSet = testAPI.findRRSet("cdn.ge.netr0.me.", "LUA")
	if luaRRSet == nil || len(luaRRSet.Comments) != 2 {
		t.Fatalf("expected 2 managed comments after delete: %#v", luaRRSet)
	}

	updatedRecord := records[0].Clone()
	updatedRecord.Value = "47.108.77.162"
	if err = provider.UpdateRecord("ge.netr0.me", records[0], updatedRecord); err != nil {
		t.Fatal(err)
	}
	records, err = provider.QueryRecords("ge.netr0.me", "cdn", dnstypes.RecordTypeA)
	if err != nil {
		t.Fatal(err)
	}
	foundUpdatedValue := false
	for _, record := range records {
		if record.Value == "47.108.77.162" {
			foundUpdatedValue = true
		}
	}
	if !foundUpdatedValue {
		t.Fatal("updated address was not returned")
	}

	serial, notifyCount := testAPI.serialAndNotifyCount()
	if serial <= 2026072601 {
		t.Fatalf("expected SOA serial to increase, got %d", serial)
	}
	if notifyCount == 0 {
		t.Fatal("expected at least one secondary notification")
	}
}

func TestPowerDNSProviderProvinceRouteCompilation(t *testing.T) {
	testAPI := newPowerDNSTestAPI()
	server := httptest.NewServer(testAPI)
	defer server.Close()

	provider := newPowerDNSTestProvider(t, server.URL)
	inputRecords := []*dnstypes.Record{
		{Name: "province-cdn", Type: dnstypes.RecordTypeA, Value: "218.244.152.85", Route: "region:Zhejiang", TTL: 60},
		{Name: "province-cdn", Type: dnstypes.RecordTypeA, Value: "8.138.241.69", Route: "country:CN", TTL: 60},
		{Name: "province-cdn", Type: dnstypes.RecordTypeA, Value: "47.108.77.161", Route: PowerDNSClosestRoute, TTL: 60},
	}
	for _, record := range inputRecords {
		if err := provider.AddRecord("ge.netr0.me", record); err != nil {
			t.Fatal(err)
		}
	}

	luaRRSet := testAPI.findRRSet("province-cdn.ge.netr0.me.", "LUA")
	if luaRRSet == nil || len(luaRRSet.Records) != 1 {
		t.Fatalf("expected managed province LUA RRset: %#v", luaRRSet)
	}
	luaContent := luaRRSet.Records[0].Content
	regionCondition := "region('ZJ')"
	countryCondition := "country('CN')"
	regionIndex := strings.Index(luaContent, regionCondition)
	countryIndex := strings.Index(luaContent, countryCondition)
	if regionIndex < 0 || countryIndex < 0 {
		t.Fatalf("expected province and country conditions in LUA content: %s", luaContent)
	}
	if regionIndex >= countryIndex {
		t.Fatalf("expected province condition before country condition: %s", luaContent)
	}
}

func TestPowerDNSProviderStandardRecords(t *testing.T) {
	testAPI := newPowerDNSTestAPI()
	server := httptest.NewServer(testAPI)
	defer server.Close()

	provider := newPowerDNSTestProvider(t, server.URL)
	cname := &dnstypes.Record{
		Name:  "www",
		Type:  dnstypes.RecordTypeCNAME,
		Value: "cdn.ge.netr0.me.",
		TTL:   120,
	}
	if err := provider.AddRecord("ge.netr0.me", cname); err != nil {
		t.Fatal(err)
	}
	queriedCNAME, err := provider.QueryRecord("ge.netr0.me", "www", dnstypes.RecordTypeCNAME)
	if err != nil {
		t.Fatal(err)
	}
	if queriedCNAME == nil || queriedCNAME.Value != cname.Value || queriedCNAME.Route != PowerDNSClosestRoute {
		t.Fatalf("unexpected CNAME: %#v", queriedCNAME)
	}
	cnameRRSet := testAPI.findRRSet("www.ge.netr0.me.", "CNAME")
	if cnameRRSet == nil || len(cnameRRSet.Records) != 1 || cnameRRSet.Records[0].Content != cname.Value {
		t.Fatalf("unexpected physical CNAME RRset: %#v", cnameRRSet)
	}

	txt := &dnstypes.Record{
		Name:  "_acme-challenge",
		Type:  dnstypes.RecordTypeTXT,
		Value: "token-value",
		TTL:   60,
	}
	if err = provider.AddRecord("ge.netr0.me", txt); err != nil {
		t.Fatal(err)
	}
	queriedTXT, err := provider.QueryRecord("ge.netr0.me", "_acme-challenge", dnstypes.RecordTypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if queriedTXT == nil || queriedTXT.Value != txt.Value {
		t.Fatalf("unexpected TXT: %#v", queriedTXT)
	}
	txtRRSet := testAPI.findRRSet("_acme-challenge.ge.netr0.me.", "TXT")
	if txtRRSet == nil || len(txtRRSet.Records) != 1 || txtRRSet.Records[0].Content != `"token-value"` {
		t.Fatalf("unexpected physical TXT RRset: %#v", txtRRSet)
	}
}

func TestPowerDNSProviderDomainsRoutesAndMask(t *testing.T) {
	testAPI := newPowerDNSTestAPI()
	server := httptest.NewServer(testAPI)
	defer server.Close()

	provider := newPowerDNSTestProvider(t, server.URL)
	domains, err := provider.GetDomains()
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0] != "ge.netr0.me" {
		t.Fatalf("unexpected domains: %#v", domains)
	}

	routes, err := provider.GetRoutes("ge.netr0.me")
	if err != nil {
		t.Fatal(err)
	}
	hasClosest := false
	hasUS := false
	hasZhejiang := false
	hasCalifornia := false
	for _, route := range routes {
		if route.Code == PowerDNSClosestRoute {
			hasClosest = true
		}
		if route.Code == "country:US" {
			hasUS = true
		}
		if route.Code == "region:Zhejiang" && route.Name == "浙江" {
			hasZhejiang = true
		}
		if route.Code == "region:CA" && route.Name == "加利福尼亚" {
			hasCalifornia = true
		}
	}
	if !hasClosest || !hasUS || !hasZhejiang || !hasCalifornia {
		t.Fatalf("unexpected routes: %#v", routes)
	}

	params := maps.Map{"apiKey": "1234567890"}
	provider.MaskParams(params)
	if params.GetString("apiKey") != "1234******" {
		t.Fatalf("API key was not masked: %s", params.GetString("apiKey"))
	}
}
