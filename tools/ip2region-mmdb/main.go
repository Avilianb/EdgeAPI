package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang/v2"
)

var chinaProvinceCodes = map[string]string{
	"北京":  "BJ",
	"天津":  "TJ",
	"河北":  "HE",
	"山西":  "SX",
	"内蒙古": "NM",
	"辽宁":  "LN",
	"吉林":  "JL",
	"黑龙江": "HL",
	"上海":  "SH",
	"江苏":  "JS",
	"浙江":  "ZJ",
	"安徽":  "AH",
	"福建":  "FJ",
	"江西":  "JX",
	"山东":  "SD",
	"河南":  "HA",
	"湖北":  "HB",
	"湖南":  "HN",
	"广东":  "GD",
	"广西":  "GX",
	"海南":  "HI",
	"重庆":  "CQ",
	"四川":  "SC",
	"贵州":  "GZ",
	"云南":  "YN",
	"西藏":  "XZ",
	"陕西":  "SN",
	"甘肃":  "GS",
	"青海":  "QH",
	"宁夏":  "NX",
	"新疆":  "XJ",
	"台湾":  "TW",
	"香港":  "HK",
	"澳门":  "MO",
}

type referenceRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type routeLocation struct {
	continentCode string
	countryCode   string
	countryName   string
	regionCode    string
	regionName    string
}

func (this routeLocation) key() string {
	return this.continentCode + "\x00" + this.countryCode + "\x00" + this.regionCode
}

func (this routeLocation) data() mmdbtype.Map {
	data := mmdbtype.Map{}
	if this.continentCode != "" {
		data["continent"] = mmdbtype.Map{
			"code": mmdbtype.String(this.continentCode),
		}
	}
	if this.countryCode != "" {
		country := mmdbtype.Map{
			"iso_code": mmdbtype.String(this.countryCode),
		}
		if this.countryName != "" {
			country["names"] = mmdbtype.Map{
				"en":    mmdbtype.String(this.countryName),
				"zh-CN": mmdbtype.String(this.countryName),
			}
		}
		data["country"] = country
		data["registered_country"] = mmdbtype.Map{
			"iso_code": mmdbtype.String(this.countryCode),
		}
	}
	if this.regionCode != "" {
		region := mmdbtype.Map{
			"iso_code": mmdbtype.String(this.regionCode),
		}
		if this.regionName != "" {
			region["names"] = mmdbtype.Map{
				"en":    mmdbtype.String(this.regionName),
				"zh-CN": mmdbtype.String(this.regionName),
			}
		}
		data["subdivisions"] = mmdbtype.Slice{region}
	}
	return data
}

type pendingRange struct {
	start    netip.Addr
	end      netip.Addr
	location routeLocation
}

type converter struct {
	reference       *maxminddb.Reader
	tree            *mmdbwriter.Tree
	regionCodeCache map[string]string

	sourceLines    int64
	insertedRanges int64
	skippedRanges  int64
}

func newConverter(referencePath string, buildEpoch int64) (*converter, error) {
	reference, err := maxminddb.Open(referencePath)
	if err != nil {
		return nil, fmt.Errorf("open reference MMDB: %w", err)
	}

	tree, err := newGeoDNSTree(buildEpoch)
	if err != nil {
		_ = reference.Close()
		return nil, err
	}

	return &converter{
		reference:       reference,
		tree:            tree,
		regionCodeCache: map[string]string{},
	}, nil
}

func newGeoDNSTree(buildEpoch int64) (*mmdbwriter.Tree, error) {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:              buildEpoch,
		DatabaseType:            "GoEdge-ip2region-GeoDNS",
		Description:             map[string]string{"en": "ip2region IPv4 and IPv6 data adapted for GoEdge PowerDNS GeoDNS"},
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
		IPVersion:               6,
		Languages:               []string{"en", "zh-CN"},
		RecordSize:              28,
	})
	if err != nil {
		return nil, fmt.Errorf("create dual-stack MMDB tree: %w", err)
	}
	return tree, nil
}

func (this *converter) close() {
	if this.reference != nil {
		_ = this.reference.Close()
	}
}

func (this *converter) convertSource(path string, ipVersion int) error {
	if ipVersion != 4 && ipVersion != 6 {
		return fmt.Errorf("unsupported IP version %d", ipVersion)
	}
	fp, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open source %q: %w", path, err)
	}
	defer func() {
		_ = fp.Close()
	}()

	scanner := bufio.NewScanner(fp)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	var pending *pendingRange

	flush := func() error {
		if pending == nil {
			return nil
		}
		err := this.tree.InsertRange(
			net.IP(pending.start.AsSlice()),
			net.IP(pending.end.AsSlice()),
			pending.location.data(),
		)
		if err != nil {
			return fmt.Errorf("insert range %s-%s: %w", pending.start, pending.end, err)
		}
		this.insertedRanges++
		pending = nil
		return nil
	}

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		this.sourceLines++

		start, end, location, err := this.parseLine(line, ipVersion)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		if location.countryCode == "" && location.continentCode == "" && location.regionCode == "" {
			this.skippedRanges++
			continue
		}

		if pending != nil &&
			pending.location.key() == location.key() &&
			pending.end.Next().IsValid() &&
			pending.end.Next() == start {
			pending.end = end
			continue
		}

		if err = flush(); err != nil {
			return err
		}
		pending = &pendingRange{
			start:    start,
			end:      end,
			location: location,
		}
	}
	if err = scanner.Err(); err != nil {
		return fmt.Errorf("read source %q: %w", path, err)
	}
	return flush()
}

func (this *converter) parseLine(line string, ipVersion int) (netip.Addr, netip.Addr, routeLocation, error) {
	fields := strings.Split(line, "|")
	if len(fields) != 7 {
		return netip.Addr{}, netip.Addr{}, routeLocation{}, fmt.Errorf("expected 7 fields, got %d", len(fields))
	}

	start, err := netip.ParseAddr(strings.TrimSpace(fields[0]))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, routeLocation{}, fmt.Errorf("parse start IP: %w", err)
	}
	end, err := netip.ParseAddr(strings.TrimSpace(fields[1]))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, routeLocation{}, fmt.Errorf("parse end IP: %w", err)
	}
	start = start.Unmap()
	end = end.Unmap()
	if start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, routeLocation{}, errors.New("invalid IP range")
	}
	expectedBitLength := 32
	if ipVersion == 6 {
		expectedBitLength = 128
	}
	if start.BitLen() != expectedBitLength {
		sourceIPVersion := 4
		if start.BitLen() == 128 {
			sourceIPVersion = 6
		}
		return netip.Addr{}, netip.Addr{}, routeLocation{}, fmt.Errorf("source contains IPv%d data, expected IPv%d", sourceIPVersion, ipVersion)
	}

	countryName := cleanValue(fields[2])
	provinceName := cleanValue(fields[3])
	countryCode := strings.ToUpper(cleanValue(fields[6]))
	if len(countryCode) != 2 {
		countryCode = ""
	}

	reference := this.lookupReference(start)
	if countryCode == "" {
		countryCode = reference.Country.ISOCode
		if countryCode == "" {
			countryCode = reference.RegisteredCountry.ISOCode
		}
	}

	continentCode := reference.Continent.Code
	regionCode := this.resolveRegionCode(countryCode, provinceName, reference)

	return start, end, routeLocation{
		continentCode: continentCode,
		countryCode:   countryCode,
		countryName:   countryName,
		regionCode:    regionCode,
		regionName:    provinceName,
	}, nil
}

func (this *converter) lookupReference(ip netip.Addr) referenceRecord {
	var record referenceRecord
	result := this.reference.Lookup(ip)
	if result.Found() {
		_ = result.Decode(&record)
	}
	return record
}

func (this *converter) resolveRegionCode(countryCode string, provinceName string, reference referenceRecord) string {
	if provinceName == "" {
		return ""
	}
	if countryCode == "CN" {
		return chinaProvinceCodes[normalizeChinaProvinceName(provinceName)]
	}

	cacheKey := countryCode + "\x00" + strings.ToLower(provinceName)
	if code := this.regionCodeCache[cacheKey]; code != "" {
		return code
	}

	if len(reference.Subdivisions) > 0 {
		subdivision := reference.Subdivisions[0]
		referenceCountryCode := reference.Country.ISOCode
		if referenceCountryCode == "" {
			referenceCountryCode = reference.RegisteredCountry.ISOCode
		}
		if subdivision.ISOCode != "" &&
			referenceCountryCode == countryCode &&
			referenceRegionMatches(provinceName, subdivision.Names) {
			this.regionCodeCache[cacheKey] = subdivision.ISOCode
			return subdivision.ISOCode
		}
	}

	// PowerDNS compares region() with subdivisions[0].iso_code. When the
	// reference database has no ISO subdivision code, retain the ip2region
	// province name so custom region:<name> routes still work.
	return provinceName
}

func (this *converter) write(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	fp, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	_, writeErr := this.tree.WriteTo(fp)
	closeErr := fp.Close()
	if writeErr != nil {
		return fmt.Errorf("write output: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close output: %w", closeErr)
	}
	return nil
}

func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "0", "Reserved":
		return ""
	default:
		return value
	}
}

func normalizeChinaProvinceName(name string) string {
	name = strings.TrimSpace(name)
	for _, suffix := range []string{
		"壮族自治区",
		"回族自治区",
		"维吾尔自治区",
		"特别行政区",
		"自治区",
		"省",
		"市",
	} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

func referenceRegionMatches(sourceName string, names map[string]string) bool {
	sourceName = normalizeRegionName(sourceName)
	if sourceName == "" {
		return false
	}
	for _, name := range names {
		if normalizeRegionName(name) == sourceName {
			return true
		}
	}
	return false
}

func normalizeRegionName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.NewReplacer(
		" ", "",
		"-", "",
		"_", "",
		".", "",
		"'", "",
		"’", "",
	).Replace(name)
	return name
}

func main() {
	ipv4Source := flag.String("ipv4-source", "", "ip2region data/ipv4_source.txt")
	ipv6Source := flag.String("ipv6-source", "", "ip2region data/ipv6_source.txt")
	referenceMMDB := flag.String("reference-mmdb", "", "existing city MMDB used only for continent and ISO subdivision codes")
	output := flag.String("output", "", "PowerDNS-compatible dual-stack MMDB output")
	buildEpoch := flag.Int64("build-epoch", time.Now().Unix(), "MMDB build epoch")
	flag.Parse()

	if *ipv4Source == "" || *ipv6Source == "" || *referenceMMDB == "" || *output == "" {
		flag.Usage()
		os.Exit(2)
	}

	converter, err := newConverter(*referenceMMDB, *buildEpoch)
	if err != nil {
		exitError(err)
	}
	defer converter.close()

	startedAt := time.Now()
	if err = converter.convertSource(*ipv4Source, 4); err != nil {
		exitError(err)
	}
	if err = converter.convertSource(*ipv6Source, 6); err != nil {
		exitError(err)
	}
	if err = converter.write(*output); err != nil {
		exitError(err)
	}

	stat, err := os.Stat(*output)
	if err != nil {
		exitError(err)
	}
	fmt.Printf(
		"source_lines=%d inserted_ranges=%d skipped_ranges=%d output_bytes=%d elapsed=%s\n",
		converter.sourceLines,
		converter.insertedRanges,
		converter.skippedRanges,
		stat.Size(),
		time.Since(startedAt).Round(time.Millisecond),
	)
}

func exitError(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
