package services

import (
	"errors"
	"testing"

	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
)

func TestEncodeNodeHTTP3Policies(t *testing.T) {
	policies, err := encodeNodeHTTP3Policies([]int64{10, 20, 30}, func(clusterId int64) (*nodeconfigs.HTTP3Policy, error) {
		if clusterId == 20 {
			return nil, nil
		}
		return &nodeconfigs.HTTP3Policy{
			IsOn:                  clusterId == 10,
			Port:                  int(4400 + clusterId),
			SupportMobileBrowsers: clusterId == 30,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}
	if policies[0].NodeClusterId != 10 {
		t.Fatalf("expected first cluster id 10, got %d", policies[0].NodeClusterId)
	}
	if len(policies[0].Http3PolicyJSON) == 0 {
		t.Fatal("expected first policy JSON")
	}
	if policies[1].NodeClusterId != 30 {
		t.Fatalf("expected second cluster id 30, got %d", policies[1].NodeClusterId)
	}
	if string(policies[1].Http3PolicyJSON) != `{"isOn":false,"port":4430,"supportMobileBrowsers":true}` {
		t.Fatalf("unexpected second policy JSON: %s", policies[1].Http3PolicyJSON)
	}
}

func TestEncodeNodeHTTP3PoliciesReturnsLookupError(t *testing.T) {
	expectedErr := errors.New("lookup failed")
	_, err := encodeNodeHTTP3Policies([]int64{10}, func(clusterId int64) (*nodeconfigs.HTTP3Policy, error) {
		return nil, expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected lookup error, got %v", err)
	}
}
