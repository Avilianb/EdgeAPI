package dnsclients

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	teaconst "github.com/TeaOSLab/EdgeAPI/internal/const"
	"github.com/TeaOSLab/EdgeAPI/internal/dnsclients/dnstypes"
	"github.com/TeaOSLab/EdgeAPI/internal/dnsclients/powerdns"
	"github.com/TeaOSLab/EdgeAPI/internal/errors"
	"github.com/iwind/TeaGo/maps"
)

const (
	PowerDNSDefaultRoute         = "default"
	PowerDNSClosestRoute         = "closest"
	powerDNSManagedCommentPrefix = "goedge-record-v1:"
	powerDNSManagedAccount       = "goedge"
)

var powerDNSChinaProvinceRoutes = []struct {
	Region string
	Code   string
	Name   string
}{
	{Region: "Beijing", Code: "BJ", Name: "北京"},
	{Region: "Tianjin", Code: "TJ", Name: "天津"},
	{Region: "Hebei", Code: "HE", Name: "河北"},
	{Region: "Shanxi", Code: "SX", Name: "山西"},
	{Region: "Inner Mongolia", Code: "NM", Name: "内蒙古"},
	{Region: "Liaoning", Code: "LN", Name: "辽宁"},
	{Region: "Jilin", Code: "JL", Name: "吉林"},
	{Region: "Heilongjiang", Code: "HL", Name: "黑龙江"},
	{Region: "Shanghai", Code: "SH", Name: "上海"},
	{Region: "Jiangsu", Code: "JS", Name: "江苏"},
	{Region: "Zhejiang", Code: "ZJ", Name: "浙江"},
	{Region: "Anhui", Code: "AH", Name: "安徽"},
	{Region: "Fujian", Code: "FJ", Name: "福建"},
	{Region: "Jiangxi", Code: "JX", Name: "江西"},
	{Region: "Shandong", Code: "SD", Name: "山东"},
	{Region: "Henan", Code: "HA", Name: "河南"},
	{Region: "Hubei", Code: "HB", Name: "湖北"},
	{Region: "Hunan", Code: "HN", Name: "湖南"},
	{Region: "Guangdong", Code: "GD", Name: "广东"},
	{Region: "Guangxi", Code: "GX", Name: "广西"},
	{Region: "Hainan", Code: "HI", Name: "海南"},
	{Region: "Chongqing", Code: "CQ", Name: "重庆"},
	{Region: "Sichuan", Code: "SC", Name: "四川"},
	{Region: "Guizhou", Code: "GZ", Name: "贵州"},
	{Region: "Yunnan", Code: "YN", Name: "云南"},
	{Region: "Tibet", Code: "XZ", Name: "西藏"},
	{Region: "Shaanxi", Code: "SN", Name: "陕西"},
	{Region: "Gansu", Code: "GS", Name: "甘肃"},
	{Region: "Qinghai", Code: "QH", Name: "青海"},
	{Region: "Ningxia", Code: "NX", Name: "宁夏"},
	{Region: "Xinjiang", Code: "XJ", Name: "新疆"},
}

// PowerDNSProvider connects GoEdge's logical per-route records to PowerDNS
// Authoritative RRsets. A/AAAA records are compiled into managed LUA records
// so PowerDNS can perform asynchronous port checks and GeoIP-based selection.
type PowerDNSProvider struct {
	BaseProvider

	ProviderId int64

	apiBaseURL         string
	apiKey             string
	serverId           string
	healthPort         int
	insecureSkipVerify bool
	routes             []*dnstypes.Route
	routeCodes         map[string]bool
	httpClient         *http.Client
}

// Auth validates and initializes the PowerDNS API connection settings.
//
// Parameters:
//   - endpoint: PowerDNS webserver URL, with or without /api/v1
//   - apiKey: PowerDNS api-key
//   - serverId: PowerDNS server ID, normally "localhost"
//   - healthPort: TCP port checked by LUA records; defaults to 443
//   - routes: optional "code|name" lines for region/country/continent routes
//   - insecureSkipVerify: allow self-signed HTTPS API certificates
func (this *PowerDNSProvider) Auth(params maps.Map) error {
	endpoint := strings.TrimSpace(params.GetString("endpoint"))
	if len(endpoint) == 0 {
		return errors.New("'endpoint' should not be empty")
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || len(parsedURL.Host) == 0 {
		return errors.New("'endpoint' should be a valid http or https URL")
	}

	endpoint = strings.TrimRight(endpoint, "/")
	if index := strings.Index(endpoint, "/api/v1"); index >= 0 {
		endpoint = endpoint[:index] + "/api/v1"
	} else {
		endpoint += "/api/v1"
	}
	this.apiBaseURL = endpoint

	this.apiKey = params.GetString("apiKey")
	if len(this.apiKey) == 0 {
		return errors.New("'apiKey' should not be empty")
	}

	this.serverId = strings.TrimSpace(params.GetString("serverId"))
	if len(this.serverId) == 0 {
		this.serverId = "localhost"
	}

	this.healthPort = params.GetInt("healthPort")
	if this.healthPort == 0 {
		this.healthPort = 443
	}
	if this.healthPort < 0 || this.healthPort > 65535 {
		return errors.New("'healthPort' should be between 0 and 65535")
	}

	this.insecureSkipVerify = params.GetBool("insecureSkipVerify")
	this.httpClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: this.insecureSkipVerify,
			},
		},
	}

	this.routes, this.routeCodes, err = parsePowerDNSRoutes(params.GetString("routes"))
	return err
}

// MaskParams masks the PowerDNS API key in administrator responses.
func (this *PowerDNSProvider) MaskParams(params maps.Map) {
	if params == nil {
		return
	}
	params["apiKey"] = MaskString(params.GetString("apiKey"))
}

// GetDomains lists zones available on the configured PowerDNS server.
func (this *PowerDNSProvider) GetDomains() (domains []string, err error) {
	zones := []powerdns.Zone{}
	err = this.doAPI(http.MethodGet, this.serverPath()+"/zones", nil, &zones)
	if err != nil {
		return nil, err
	}

	for _, zone := range zones {
		name := strings.TrimSuffix(strings.TrimSpace(zone.Name), ".")
		if len(name) > 0 {
			domains = append(domains, name)
		}
	}
	sort.Strings(domains)
	return domains, nil
}

// GetRecords expands managed PowerDNS RRsets back into GoEdge logical records.
func (this *PowerDNSProvider) GetRecords(domain string) (records []*dnstypes.Record, err error) {
	zone, err := this.getZone(domain)
	if err != nil {
		return nil, err
	}
	records, err = this.logicalRecordsFromZone(domain, zone)
	if err != nil {
		return nil, err
	}
	sort.Slice(records, func(i int, j int) bool {
		left := records[i].Name + "\x00" + records[i].Type + "\x00" + records[i].Route + "\x00" + records[i].Value
		right := records[j].Name + "\x00" + records[j].Type + "\x00" + records[j].Route + "\x00" + records[j].Value
		return left < right
	})
	return records, nil
}

// GetRoutes returns PowerDNS GeoDNS routes. Additional region/country/continent
// routes can be supplied in the provider settings.
func (this *PowerDNSProvider) GetRoutes(domain string) (routes []*dnstypes.Route, err error) {
	for _, route := range this.routes {
		routes = append(routes, &dnstypes.Route{
			Name: route.Name,
			Code: route.Code,
		})
	}
	return routes, nil
}

// QueryRecord returns the first matching logical record.
func (this *PowerDNSProvider) QueryRecord(domain string, name string, recordType dnstypes.RecordType) (*dnstypes.Record, error) {
	records, err := this.QueryRecords(domain, name, recordType)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return records[0], nil
}

// QueryRecords returns all logical records for a name and type.
func (this *PowerDNSProvider) QueryRecords(domain string, name string, recordType dnstypes.RecordType) (result []*dnstypes.Record, err error) {
	records, err := this.GetRecords(domain)
	if err != nil {
		return nil, err
	}
	name = normalizePowerDNSRelativeName(name)
	for _, record := range records {
		if normalizePowerDNSRelativeName(record.Name) == name && record.Type == recordType {
			result = append(result, record)
		}
	}
	return result, nil
}

// AddRecord adds a logical record and rewrites its managed RRset.
func (this *PowerDNSProvider) AddRecord(domain string, newRecord *dnstypes.Record) error {
	record, err := this.normalizeRecord(domain, newRecord)
	if err != nil {
		return this.WrapError(err, domain, newRecord)
	}

	zone, err := this.getZone(domain)
	if err != nil {
		return this.WrapError(err, domain, record)
	}
	records, err := this.logicalRecordsFromZone(domain, zone)
	if err != nil {
		return this.WrapError(err, domain, record)
	}

	for _, existingRecord := range records {
		if samePowerDNSLogicalRecord(existingRecord, record) {
			newRecord.Id = existingRecord.Id
			return nil
		}
	}

	records = append(records, record)
	err = this.syncRecordGroup(domain, zone, records, record.Name, record.Type)
	if err == nil {
		newRecord.Id = record.Id
	}
	return this.WrapError(err, domain, record)
}

// UpdateRecord updates one logical record and rewrites affected RRsets.
func (this *PowerDNSProvider) UpdateRecord(domain string, record *dnstypes.Record, newRecord *dnstypes.Record) error {
	normalizedNewRecord, err := this.normalizeRecord(domain, newRecord)
	if err != nil {
		return this.WrapError(err, domain, newRecord)
	}

	zone, err := this.getZone(domain)
	if err != nil {
		return this.WrapError(err, domain, newRecord)
	}
	records, err := this.logicalRecordsFromZone(domain, zone)
	if err != nil {
		return this.WrapError(err, domain, newRecord)
	}

	recordIndex := findPowerDNSLogicalRecord(records, record)
	if recordIndex < 0 {
		return this.AddRecord(domain, newRecord)
	}

	oldRecord := records[recordIndex]
	normalizedNewRecord.Id = oldRecord.Id
	for index, existingRecord := range records {
		if index != recordIndex && samePowerDNSLogicalRecord(existingRecord, normalizedNewRecord) {
			return this.WrapError(errors.New("record already exists"), domain, normalizedNewRecord)
		}
	}
	records[recordIndex] = normalizedNewRecord

	oldGroup := powerDNSRecordGroupKey(oldRecord)
	newGroup := powerDNSRecordGroupKey(normalizedNewRecord)
	err = this.syncRecordGroup(domain, zone, records, oldRecord.Name, oldRecord.Type)
	if err != nil {
		return this.WrapError(err, domain, normalizedNewRecord)
	}
	if oldGroup != newGroup {
		zone, err = this.getZone(domain)
		if err != nil {
			return this.WrapError(err, domain, normalizedNewRecord)
		}
		err = this.syncRecordGroup(domain, zone, records, normalizedNewRecord.Name, normalizedNewRecord.Type)
		if err != nil {
			return this.WrapError(err, domain, normalizedNewRecord)
		}
	}

	newRecord.Id = normalizedNewRecord.Id
	return nil
}

// DeleteRecord deletes one logical record and rewrites its managed RRset.
func (this *PowerDNSProvider) DeleteRecord(domain string, record *dnstypes.Record) error {
	zone, err := this.getZone(domain)
	if err != nil {
		return this.WrapError(err, domain, record)
	}
	records, err := this.logicalRecordsFromZone(domain, zone)
	if err != nil {
		return this.WrapError(err, domain, record)
	}

	recordIndex := findPowerDNSLogicalRecord(records, record)
	if recordIndex < 0 {
		return nil
	}
	oldRecord := records[recordIndex]
	records = append(records[:recordIndex], records[recordIndex+1:]...)
	err = this.syncRecordGroup(domain, zone, records, oldRecord.Name, oldRecord.Type)
	return this.WrapError(err, domain, oldRecord)
}

// DefaultRoute makes unassigned GoEdge nodes participate in closest-node
// GeoDNS automatically.
func (this *PowerDNSProvider) DefaultRoute() string {
	return PowerDNSClosestRoute
}

func (this *PowerDNSProvider) getZone(domain string) (*powerdns.Zone, error) {
	zone := new(powerdns.Zone)
	zoneID := powerDNSZoneName(domain)
	err := this.doAPI(http.MethodGet, this.serverPath()+"/zones/"+url.PathEscape(zoneID), nil, zone)
	if err != nil {
		return nil, err
	}
	if len(zone.ID) == 0 {
		zone.ID = zoneID
	}
	return zone, nil
}

func (this *PowerDNSProvider) syncRecordGroup(domain string, zone *powerdns.Zone, allRecords []*dnstypes.Record, name string, recordType dnstypes.RecordType) error {
	if recordType == dnstypes.RecordTypeA || recordType == dnstypes.RecordTypeAAAA {
		return this.syncAddressRecords(domain, zone, allRecords, name)
	}
	return this.syncStandardRecords(domain, zone, allRecords, name, recordType)
}

func (this *PowerDNSProvider) syncAddressRecords(domain string, zone *powerdns.Zone, allRecords []*dnstypes.Record, name string) error {
	name = normalizePowerDNSRelativeName(name)
	fqdn := powerDNSRecordName(domain, name)
	addressRecords := []*dnstypes.Record{}
	for _, record := range allRecords {
		if normalizePowerDNSRelativeName(record.Name) == name &&
			(record.Type == dnstypes.RecordTypeA || record.Type == dnstypes.RecordTypeAAAA) {
			addressRecords = append(addressRecords, record)
		}
	}

	patch := powerdns.PatchZoneRequest{}
	for _, rrset := range zone.RRSets {
		if !strings.EqualFold(rrset.Name, fqdn) {
			continue
		}
		switch rrset.Type {
		case dnstypes.RecordTypeA, dnstypes.RecordTypeAAAA:
			patch.RRSets = append(patch.RRSets, powerdns.RRSet{
				Name:       rrset.Name,
				Type:       rrset.Type,
				ChangeType: "DELETE",
			})
		case "LUA":
			if !powerDNSRRSetIsManaged(rrset) {
				return errors.New("an unmanaged LUA RRset already exists for '" + fqdn + "'")
			}
			if len(addressRecords) == 0 {
				patch.RRSets = append(patch.RRSets, powerdns.RRSet{
					Name:       rrset.Name,
					Type:       rrset.Type,
					ChangeType: "DELETE",
				})
			}
		}
	}

	if len(addressRecords) > 0 {
		luaRecords := []powerdns.Record{}
		for _, addressType := range []dnstypes.RecordType{dnstypes.RecordTypeA, dnstypes.RecordTypeAAAA} {
			familyRecords := filterPowerDNSRecords(addressRecords, name, addressType)
			if len(familyRecords) == 0 {
				continue
			}
			luaContent, err := this.compileAddressLuaRecord(addressType, familyRecords)
			if err != nil {
				return err
			}
			luaRecords = append(luaRecords, powerdns.Record{
				Content:  luaContent,
				Disabled: false,
			})
		}
		patch.RRSets = append(patch.RRSets, powerdns.RRSet{
			Name:       fqdn,
			Type:       "LUA",
			TTL:        powerDNSRecordsTTL(addressRecords, this.MinTTL()),
			ChangeType: "REPLACE",
			Records:    luaRecords,
			Comments:   encodePowerDNSManagedComments(addressRecords),
		})
	}

	return this.patchZone(zone.ID, patch)
}

func (this *PowerDNSProvider) syncStandardRecords(domain string, zone *powerdns.Zone, allRecords []*dnstypes.Record, name string, recordType dnstypes.RecordType) error {
	if recordType != dnstypes.RecordTypeCNAME && recordType != dnstypes.RecordTypeTXT {
		return errors.New("unsupported record type '" + recordType + "'")
	}

	name = normalizePowerDNSRelativeName(name)
	fqdn := powerDNSRecordName(domain, name)
	records := filterPowerDNSRecords(allRecords, name, recordType)
	if recordType == dnstypes.RecordTypeCNAME && len(uniquePowerDNSRecordValues(records)) > 1 {
		return errors.New("PowerDNS can only store one CNAME target per name")
	}

	existing := false
	for _, rrset := range zone.RRSets {
		if strings.EqualFold(rrset.Name, fqdn) && rrset.Type == recordType {
			existing = true
			break
		}
	}
	if !existing && len(records) == 0 {
		return nil
	}

	rrset := powerdns.RRSet{
		Name:       fqdn,
		Type:       recordType,
		ChangeType: "DELETE",
	}
	if len(records) > 0 {
		rrset.ChangeType = "REPLACE"
		rrset.TTL = powerDNSRecordsTTL(records, this.MinTTL())
		rrset.Comments = encodePowerDNSManagedComments(records)
		for _, record := range records {
			content, err := powerDNSRecordContent(record)
			if err != nil {
				return err
			}
			rrset.Records = append(rrset.Records, powerdns.Record{
				Content:  content,
				Disabled: false,
			})
		}
	}

	return this.patchZone(zone.ID, powerdns.PatchZoneRequest{
		RRSets: []powerdns.RRSet{rrset},
	})
}

func (this *PowerDNSProvider) patchZone(zoneID string, patch powerdns.PatchZoneRequest) error {
	if len(patch.RRSets) == 0 {
		return nil
	}

	zonePath := this.serverPath() + "/zones/" + url.PathEscape(zoneID)
	if err := this.doAPI(http.MethodPatch, zonePath, patch, nil); err != nil {
		return err
	}

	shouldNotify, err := this.bumpSOASerial(zonePath)
	if err != nil {
		return err
	}
	if shouldNotify {
		if err = this.doAPI(http.MethodPut, zonePath+"/notify", nil, nil); err != nil {
			return fmt.Errorf("notify PowerDNS secondaries failed: %w", err)
		}
	}
	return nil
}

func (this *PowerDNSProvider) bumpSOASerial(zonePath string) (shouldNotify bool, err error) {
	zone := new(powerdns.Zone)
	if err = this.doAPI(http.MethodGet, zonePath, nil, zone); err != nil {
		return false, fmt.Errorf("read PowerDNS zone before SOA update failed: %w", err)
	}

	for _, rrset := range zone.RRSets {
		if rrset.Type != "SOA" {
			continue
		}
		if len(rrset.Records) != 1 {
			return false, errors.New("PowerDNS zone should contain exactly one SOA record")
		}

		fields := strings.Fields(rrset.Records[0].Content)
		if len(fields) != 7 {
			return false, errors.New("invalid PowerDNS SOA record content")
		}
		serial, parseErr := strconv.ParseUint(fields[2], 10, 32)
		if parseErr != nil {
			return false, fmt.Errorf("invalid PowerDNS SOA serial: %w", parseErr)
		}
		serial++
		if serial > uint64(^uint32(0)) {
			serial = 1
		}
		fields[2] = strconv.FormatUint(serial, 10)

		soaRRSet := rrset
		soaRRSet.ChangeType = "REPLACE"
		soaRRSet.Records = []powerdns.Record{{
			Content:  strings.Join(fields, " "),
			Disabled: false,
		}}
		if err = this.doAPI(http.MethodPatch, zonePath, powerdns.PatchZoneRequest{
			RRSets: []powerdns.RRSet{soaRRSet},
		}, nil); err != nil {
			return false, fmt.Errorf("increase PowerDNS SOA serial failed: %w", err)
		}

		switch strings.ToLower(zone.Kind) {
		case "master", "primary":
			return true, nil
		default:
			return false, nil
		}
	}

	return false, errors.New("PowerDNS zone has no SOA record")
}

func (this *PowerDNSProvider) logicalRecordsFromZone(domain string, zone *powerdns.Zone) ([]*dnstypes.Record, error) {
	records := []*dnstypes.Record{}
	managedRRSetKeys := map[string]bool{}
	managedAddressNames := map[string]bool{}

	for _, rrset := range zone.RRSets {
		managedRecords, managed, err := decodePowerDNSManagedComments(rrset.Comments)
		if err != nil {
			return nil, err
		}
		if !managed {
			continue
		}
		records = append(records, managedRecords...)
		managedRRSetKeys[strings.ToLower(rrset.Name)+"\x00"+rrset.Type] = true
		if rrset.Type == "LUA" {
			managedAddressNames[strings.ToLower(rrset.Name)] = true
		}
	}

	for _, rrset := range zone.RRSets {
		rrsetKey := strings.ToLower(rrset.Name) + "\x00" + rrset.Type
		if managedRRSetKeys[rrsetKey] {
			continue
		}
		if (rrset.Type == dnstypes.RecordTypeA || rrset.Type == dnstypes.RecordTypeAAAA) &&
			managedAddressNames[strings.ToLower(rrset.Name)] {
			continue
		}
		if rrset.Type != dnstypes.RecordTypeA &&
			rrset.Type != dnstypes.RecordTypeAAAA &&
			rrset.Type != dnstypes.RecordTypeCNAME &&
			rrset.Type != dnstypes.RecordTypeTXT {
			continue
		}

		relativeName := powerDNSRelativeName(domain, rrset.Name)
		for _, apiRecord := range rrset.Records {
			if apiRecord.Disabled {
				continue
			}
			value, err := parsePowerDNSRecordContent(rrset.Type, apiRecord.Content)
			if err != nil {
				return nil, err
			}
			record := &dnstypes.Record{
				Name:  relativeName,
				Type:  rrset.Type,
				Value: value,
				Route: this.DefaultRoute(),
				TTL:   rrset.TTL,
			}
			record.Id = powerDNSLogicalRecordID(domain, record)
			records = append(records, record)
		}
	}

	return records, nil
}

func (this *PowerDNSProvider) normalizeRecord(domain string, source *dnstypes.Record) (*dnstypes.Record, error) {
	if source == nil {
		return nil, errors.New("record should not be nil")
	}
	record := source.Clone()
	record.Name = normalizePowerDNSRelativeName(record.Name)
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Value = strings.TrimSpace(record.Value)
	record.Route = strings.TrimSpace(record.Route)
	if len(record.Route) == 0 {
		record.Route = this.DefaultRoute()
	}
	if !this.routeCodes[record.Route] {
		return nil, errors.New("unsupported PowerDNS route '" + record.Route + "'")
	}

	switch record.Type {
	case dnstypes.RecordTypeA:
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("invalid IPv4 address '" + record.Value + "'")
		}
		record.Value = ip.To4().String()
	case dnstypes.RecordTypeAAAA:
		ip := net.ParseIP(record.Value)
		if ip == nil || ip.To4() != nil {
			return nil, errors.New("invalid IPv6 address '" + record.Value + "'")
		}
		record.Value = ip.String()
	case dnstypes.RecordTypeCNAME:
		if len(record.Value) == 0 {
			return nil, errors.New("CNAME target should not be empty")
		}
		if !strings.HasSuffix(record.Value, ".") {
			record.Value += "."
		}
	case dnstypes.RecordTypeTXT:
		if len(record.Value) == 0 {
			return nil, errors.New("TXT value should not be empty")
		}
	default:
		return nil, errors.New("unsupported record type '" + record.Type + "'")
	}

	if record.TTL <= 0 {
		record.TTL = powerDNSRecordsTTL([]*dnstypes.Record{record}, this.MinTTL())
	}
	if len(record.Id) == 0 {
		record.Id = powerDNSLogicalRecordID(domain, record)
	}
	return record, nil
}

func (this *PowerDNSProvider) compileAddressLuaRecord(recordType dnstypes.RecordType, records []*dnstypes.Record) (string, error) {
	groups := map[string][]string{}
	allValues := []string{}
	for _, record := range records {
		if record.Type != recordType {
			continue
		}
		if !this.routeCodes[record.Route] {
			return "", errors.New("unsupported PowerDNS route '" + record.Route + "'")
		}
		groups[record.Route] = appendUniquePowerDNSString(groups[record.Route], record.Value)
		allValues = appendUniquePowerDNSString(allValues, record.Value)
	}
	if len(allValues) == 0 {
		return "", errors.New("no addresses to compile")
	}

	fallback := []string{}
	fallback = appendUniquePowerDNSStrings(fallback, groups[PowerDNSClosestRoute]...)
	fallback = appendUniquePowerDNSStrings(fallback, groups[PowerDNSDefaultRoute]...)
	if len(fallback) == 0 {
		fallback = append(fallback, allValues...)
	}

	conditionRoutes := []string{}
	for route, values := range groups {
		if len(values) == 0 || route == PowerDNSClosestRoute || route == PowerDNSDefaultRoute {
			continue
		}
		if _, _, ok := parsePowerDNSRouteCondition(route); !ok {
			return "", errors.New("unsupported conditional route '" + route + "'")
		}
		conditionRoutes = append(conditionRoutes, route)
	}
	sort.Slice(conditionRoutes, func(i int, j int) bool {
		leftType, _, _ := parsePowerDNSRouteCondition(conditionRoutes[i])
		rightType, _, _ := parsePowerDNSRouteCondition(conditionRoutes[j])
		if leftType != rightType {
			return powerDNSRouteConditionPriority(leftType) < powerDNSRouteConditionPriority(rightType)
		}
		return conditionRoutes[i] < conditionRoutes[j]
	})

	if len(conditionRoutes) == 0 {
		return powerDNSLuaRecordContent(recordType, this.luaAddressSelection(allValues, nil)), nil
	}

	var script strings.Builder
	script.WriteString(";")
	for _, route := range conditionRoutes {
		conditionExpression, ok := powerDNSRouteConditionLua(route)
		if !ok {
			return "", errors.New("unsupported conditional route '" + route + "'")
		}
		script.WriteString("if ")
		script.WriteString(conditionExpression)
		script.WriteString(" then return ")
		script.WriteString(this.luaAddressSelection(groups[route], fallback))
		script.WriteString(" end;")
	}
	script.WriteString("return ")
	script.WriteString(this.luaAddressSelection(fallback, nil))

	return powerDNSLuaRecordContent(recordType, script.String()), nil
}

func (this *PowerDNSProvider) luaAddressSelection(primary []string, fallback []string) string {
	primary = uniquePowerDNSStrings(primary)
	fallback = uniquePowerDNSStrings(fallback)
	if this.healthPort <= 0 {
		return "pickclosest(" + powerDNSLuaStringList(appendUniquePowerDNSStrings(primary, fallback...)) + ")"
	}
	if len(fallback) == 0 || equalPowerDNSStringSets(primary, fallback) {
		return "ifportup(" + strconv.Itoa(this.healthPort) + "," + powerDNSLuaStringList(primary) + ",{selector='pickclosest'})"
	}
	return "ifportup(" + strconv.Itoa(this.healthPort) + ",{" +
		powerDNSLuaStringList(primary) + "," + powerDNSLuaStringList(fallback) +
		"},{selector='pickclosest'})"
}

func (this *PowerDNSProvider) serverPath() string {
	return "/servers/" + url.PathEscape(this.serverId)
}

func (this *PowerDNSProvider) doAPI(method string, apiPath string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		bodyData, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(bodyData)
	}

	req, err := http.NewRequest(method, this.apiBaseURL+apiPath, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", this.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", teaconst.ProductName+"/"+teaconst.Version)

	resp, err := this.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errorResponse := new(powerdns.ErrorResponse)
		if json.Unmarshal(data, errorResponse) == nil && len(errorResponse.Error) > 0 {
			return errors.New("PowerDNS API error: " + errorResponse.Error)
		}
		return fmt.Errorf("PowerDNS API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if result == nil || len(data) == 0 {
		return nil
	}
	if err = json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("decode PowerDNS API response failed: %w", err)
	}
	return nil
}

func parsePowerDNSRoutes(customRoutes string) ([]*dnstypes.Route, map[string]bool, error) {
	routes := []*dnstypes.Route{
		{Name: "GeoDNS 最近可用节点", Code: PowerDNSClosestRoute},
		{Name: "默认", Code: PowerDNSDefaultRoute},
		{Name: "中国", Code: "country:CN"},
		{Name: "亚洲", Code: "continent:AS"},
		{Name: "欧洲", Code: "continent:EU"},
		{Name: "北美洲", Code: "continent:NA"},
		{Name: "南美洲", Code: "continent:SA"},
		{Name: "非洲", Code: "continent:AF"},
		{Name: "大洋洲", Code: "continent:OC"},
	}
	for _, provinceRoute := range powerDNSChinaProvinceRoutes {
		routes = append(routes, &dnstypes.Route{
			Name: provinceRoute.Name,
			Code: "region:" + provinceRoute.Region,
		})
	}
	routeIndexes := map[string]int{}
	for index, route := range routes {
		routeIndexes[route.Code] = index
	}

	for _, line := range strings.Split(strings.ReplaceAll(customRoutes, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			return nil, nil, errors.New("PowerDNS route should use 'code|name': " + line)
		}
		code := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])
		if len(code) == 0 || len(name) == 0 {
			return nil, nil, errors.New("PowerDNS route code and name should not be empty")
		}
		if code != PowerDNSClosestRoute && code != PowerDNSDefaultRoute {
			if _, _, ok := parsePowerDNSRouteCondition(code); !ok {
				return nil, nil, errors.New("unsupported PowerDNS route code '" + code + "'")
			}
		}
		if index, ok := routeIndexes[code]; ok {
			routes[index].Name = name
		} else {
			routeIndexes[code] = len(routes)
			routes = append(routes, &dnstypes.Route{Name: name, Code: code})
		}
	}

	routeCodes := map[string]bool{}
	for _, route := range routes {
		routeCodes[route.Code] = true
	}
	return routes, routeCodes, nil
}

func parsePowerDNSRouteCondition(route string) (conditionType string, conditionValue string, ok bool) {
	parts := strings.SplitN(route, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	conditionType = strings.ToLower(strings.TrimSpace(parts[0]))
	conditionValue = strings.TrimSpace(parts[1])
	switch conditionType {
	case "country":
		conditionValue = strings.ToUpper(conditionValue)
		return conditionType, conditionValue, len(conditionValue) == 2
	case "continent":
		conditionValue = strings.ToUpper(conditionValue)
		switch conditionValue {
		case "AF", "AS", "EU", "NA", "OC", "SA", "AN":
			return conditionType, conditionValue, true
		}
	case "region":
		if len(conditionValue) > 0 && len(conditionValue) <= 100 && !strings.ContainsAny(conditionValue, "\r\n") {
			return conditionType, conditionValue, true
		}
	}
	return "", "", false
}

func powerDNSRouteConditionPriority(conditionType string) int {
	switch conditionType {
	case "region":
		return 0
	case "country":
		return 1
	case "continent":
		return 2
	default:
		return 3
	}
}

func powerDNSRouteConditionLua(route string) (string, bool) {
	conditionType, conditionValue, ok := parsePowerDNSRouteCondition(route)
	if !ok {
		return "", false
	}
	switch conditionType {
	case "region":
		for _, provinceRoute := range powerDNSChinaProvinceRoutes {
			if strings.EqualFold(provinceRoute.Region, conditionValue) {
				conditionValue = provinceRoute.Code
				break
			}
		}
		return "region(" + powerDNSLuaQuote(conditionValue) + ")", true
	case "country", "continent":
		return conditionType + "(" + powerDNSLuaQuote(conditionValue) + ")", true
	default:
		return "", false
	}
}

func encodePowerDNSManagedComments(records []*dnstypes.Record) []powerdns.Comment {
	comments := make([]powerdns.Comment, 0, len(records))
	modifiedAt := time.Now().Unix()
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			continue
		}
		comments = append(comments, powerdns.Comment{
			Account:    powerDNSManagedAccount,
			Content:    powerDNSManagedCommentPrefix + base64.RawURLEncoding.EncodeToString(data),
			ModifiedAt: modifiedAt,
		})
	}
	return comments
}

func decodePowerDNSManagedComments(comments []powerdns.Comment) (records []*dnstypes.Record, managed bool, err error) {
	for _, comment := range comments {
		if !strings.HasPrefix(comment.Content, powerDNSManagedCommentPrefix) {
			continue
		}
		managed = true
		data, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(comment.Content, powerDNSManagedCommentPrefix))
		if decodeErr != nil {
			return nil, true, fmt.Errorf("decode managed PowerDNS comment failed: %w", decodeErr)
		}
		record := new(dnstypes.Record)
		if decodeErr = json.Unmarshal(data, record); decodeErr != nil {
			return nil, true, fmt.Errorf("decode managed PowerDNS record failed: %w", decodeErr)
		}
		records = append(records, record)
	}
	return records, managed, nil
}

func powerDNSRRSetIsManaged(rrset powerdns.RRSet) bool {
	for _, comment := range rrset.Comments {
		if strings.HasPrefix(comment.Content, powerDNSManagedCommentPrefix) {
			return true
		}
	}
	return false
}

func powerDNSZoneName(domain string) string {
	return strings.TrimSuffix(strings.TrimSpace(domain), ".") + "."
}

func normalizePowerDNSRelativeName(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	if len(name) == 0 || name == "@" {
		return "@"
	}
	return name
}

func powerDNSRecordName(domain string, relativeName string) string {
	zoneName := powerDNSZoneName(domain)
	relativeName = normalizePowerDNSRelativeName(relativeName)
	if relativeName == "@" {
		return zoneName
	}
	return relativeName + "." + zoneName
}

func powerDNSRelativeName(domain string, fqdn string) string {
	zoneName := powerDNSZoneName(domain)
	fqdn = strings.TrimSpace(fqdn)
	if strings.EqualFold(fqdn, zoneName) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(zoneName)) {
		return normalizePowerDNSRelativeName(fqdn[:len(fqdn)-len(zoneName)-1])
	}
	return normalizePowerDNSRelativeName(fqdn)
}

func powerDNSLogicalRecordID(domain string, record *dnstypes.Record) string {
	sum := sha1.Sum([]byte(strings.ToLower(powerDNSZoneName(domain)) + "\x00" +
		strings.ToLower(normalizePowerDNSRelativeName(record.Name)) + "\x00" +
		record.Type + "\x00" + record.Route + "\x00" + record.Value))
	return hex.EncodeToString(sum[:])
}

func findPowerDNSLogicalRecord(records []*dnstypes.Record, target *dnstypes.Record) int {
	if target == nil {
		return -1
	}
	for index, record := range records {
		if len(target.Id) > 0 && record.Id == target.Id {
			return index
		}
		if samePowerDNSLogicalRecord(record, target) {
			return index
		}
	}
	return -1
}

func samePowerDNSLogicalRecord(left *dnstypes.Record, right *dnstypes.Record) bool {
	if left == nil || right == nil {
		return false
	}
	leftRoute := left.Route
	rightRoute := right.Route
	if len(leftRoute) == 0 {
		leftRoute = PowerDNSClosestRoute
	}
	if len(rightRoute) == 0 {
		rightRoute = PowerDNSClosestRoute
	}
	return normalizePowerDNSRelativeName(left.Name) == normalizePowerDNSRelativeName(right.Name) &&
		left.Type == right.Type &&
		leftRoute == rightRoute &&
		left.Value == right.Value
}

func powerDNSRecordGroupKey(record *dnstypes.Record) string {
	groupType := record.Type
	if groupType == dnstypes.RecordTypeA || groupType == dnstypes.RecordTypeAAAA {
		groupType = "ADDRESS"
	}
	return normalizePowerDNSRelativeName(record.Name) + "\x00" + groupType
}

func filterPowerDNSRecords(records []*dnstypes.Record, name string, recordType dnstypes.RecordType) []*dnstypes.Record {
	result := []*dnstypes.Record{}
	name = normalizePowerDNSRelativeName(name)
	for _, record := range records {
		if normalizePowerDNSRelativeName(record.Name) == name && record.Type == recordType {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i int, j int) bool {
		return result[i].Route+"\x00"+result[i].Value < result[j].Route+"\x00"+result[j].Value
	})
	return result
}

func powerDNSRecordsTTL(records []*dnstypes.Record, minimumTTL int32) int32 {
	var ttl int32
	for _, record := range records {
		if record.TTL > 0 && (ttl == 0 || record.TTL < ttl) {
			ttl = record.TTL
		}
	}
	if minimumTTL > ttl {
		ttl = minimumTTL
	}
	if ttl <= 0 {
		ttl = 60
	}
	return ttl
}

func powerDNSRecordContent(record *dnstypes.Record) (string, error) {
	switch record.Type {
	case dnstypes.RecordTypeCNAME:
		if strings.HasSuffix(record.Value, ".") {
			return record.Value, nil
		}
		return record.Value + ".", nil
	case dnstypes.RecordTypeTXT:
		return strconv.Quote(record.Value), nil
	default:
		return record.Value, nil
	}
}

func parsePowerDNSRecordContent(recordType string, content string) (string, error) {
	content = strings.TrimSpace(content)
	switch recordType {
	case dnstypes.RecordTypeCNAME:
		if !strings.HasSuffix(content, ".") {
			content += "."
		}
		return content, nil
	case dnstypes.RecordTypeTXT:
		if strings.HasPrefix(content, "\"") {
			value, err := strconv.Unquote(content)
			if err == nil {
				return value, nil
			}
		}
		return content, nil
	default:
		return content, nil
	}
}

func powerDNSLuaRecordContent(recordType string, script string) string {
	const maxSegmentLength = 240
	segments := []string{}
	for len(script) > 0 {
		length := len(script)
		if length > maxSegmentLength {
			length = maxSegmentLength
		}
		segments = append(segments, strconv.Quote(script[:length]))
		script = script[length:]
	}
	return recordType + " " + strings.Join(segments, " ")
}

func powerDNSLuaStringList(values []string) string {
	quotedValues := make([]string, 0, len(values))
	for _, value := range uniquePowerDNSStrings(values) {
		quotedValues = append(quotedValues, powerDNSLuaQuote(value))
	}
	return "{" + strings.Join(quotedValues, ",") + "}"
}

func powerDNSLuaQuote(value string) string {
	value = strings.NewReplacer(
		"\\", "\\\\",
		"'", "\\'",
		"\r", "\\r",
		"\n", "\\n",
	).Replace(value)
	return "'" + value + "'"
}

func uniquePowerDNSRecordValues(records []*dnstypes.Record) []string {
	values := []string{}
	for _, record := range records {
		values = appendUniquePowerDNSString(values, record.Value)
	}
	return values
}

func appendUniquePowerDNSString(values []string, value string) []string {
	for _, existingValue := range values {
		if existingValue == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniquePowerDNSStrings(values []string, additionalValues ...string) []string {
	for _, value := range additionalValues {
		values = appendUniquePowerDNSString(values, value)
	}
	return values
}

func uniquePowerDNSStrings(values []string) []string {
	return appendUniquePowerDNSStrings(nil, values...)
}

func equalPowerDNSStringSets(left []string, right []string) bool {
	left = uniquePowerDNSStrings(left)
	right = uniquePowerDNSStrings(right)
	if len(left) != len(right) {
		return false
	}
	sort.Strings(left)
	sort.Strings(right)
	for index, value := range left {
		if value != right[index] {
			return false
		}
	}
	return true
}
