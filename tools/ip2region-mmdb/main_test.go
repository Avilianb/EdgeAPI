package main

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang/v2"
)

func TestNormalizeChinaProvinceName(t *testing.T) {
	tests := map[string]string{
		"广东省":      "广东",
		"北京市":      "北京",
		"广西壮族自治区":  "广西",
		"宁夏回族自治区":  "宁夏",
		"新疆维吾尔自治区": "新疆",
		"内蒙古自治区":   "内蒙古",
		"香港特别行政区":  "香港",
		"  黑龙江省  ": "黑龙江",
	}
	for source, expected := range tests {
		if actual := normalizeChinaProvinceName(source); actual != expected {
			t.Fatalf("normalizeChinaProvinceName(%q) = %q, want %q", source, actual, expected)
		}
	}
}

func TestReferenceRegionMatches(t *testing.T) {
	names := map[string]string{
		"en":    "South Holland",
		"zh-CN": "南荷兰省",
	}
	if !referenceRegionMatches("south-holland", names) {
		t.Fatal("expected normalized English region name to match")
	}
	if !referenceRegionMatches("南荷兰省", names) {
		t.Fatal("expected Chinese region name to match")
	}
	if referenceRegionMatches("California", names) {
		t.Fatal("unexpected region match")
	}
}

func TestCleanValue(t *testing.T) {
	for _, value := range []string{"", "0", "Reserved", " Reserved "} {
		if cleanValue(value) != "" {
			t.Fatalf("cleanValue(%q) should be empty", value)
		}
	}
	if cleanValue(" 广东省 ") != "广东省" {
		t.Fatal("expected surrounding whitespace to be removed")
	}
}

func TestGeoDNSTreeSupportsIPv4AndIPv6(t *testing.T) {
	tree, err := newGeoDNSTree(1)
	if err != nil {
		t.Fatal(err)
	}

	ipv4 := net.ParseIP("223.5.5.5")
	ipv6 := net.ParseIP("2400:3200::1")
	if err = tree.InsertRange(ipv4, ipv4, routeLocation{
		continentCode: "AS",
		countryCode:   "CN",
		regionCode:    "ZJ",
	}.data()); err != nil {
		t.Fatal(err)
	}
	if err = tree.InsertRange(ipv6, ipv6, routeLocation{
		continentCode: "AS",
		countryCode:   "CN",
		regionCode:    "ZJ",
	}.data()); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "dual-stack.mmdb")
	fp, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tree.WriteTo(fp); err != nil {
		_ = fp.Close()
		t.Fatal(err)
	}
	if err = fp.Close(); err != nil {
		t.Fatal(err)
	}

	reader, err := maxminddb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	for _, address := range []string{"223.5.5.5", "2400:3200::1"} {
		var record referenceRecord
		result := reader.Lookup(netip.MustParseAddr(address))
		if !result.Found() {
			t.Fatalf("expected %s to be present", address)
		}
		if err = result.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.Country.ISOCode != "CN" ||
			len(record.Subdivisions) != 1 ||
			record.Subdivisions[0].ISOCode != "ZJ" {
			t.Fatalf("unexpected %s record: %#v", address, record)
		}
	}
}
