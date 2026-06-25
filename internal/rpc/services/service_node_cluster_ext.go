// Copyright 2023 GoEdge CDN goedge.cdn@gmail.com. All rights reserved. Official site: https://goedge.cloud .
//go:build !plus

package services

import (
	"context"
	"encoding/json"

	"github.com/TeaOSLab/EdgeAPI/internal/db/models"
	"github.com/TeaOSLab/EdgeCommon/pkg/rpc/pb"
)

func (this *NodeClusterService) FindNodeClusterHTTP3Policy(ctx context.Context, req *pb.FindNodeClusterHTTP3PolicyRequest) (*pb.FindNodeClusterHTTP3PolicyResponse, error) {
	_, _, err := this.ValidateAdminAndUser(ctx, false)
	if err != nil {
		return nil, err
	}

	var tx = this.NullTx()
	policy, err := models.SharedNodeClusterDAO.FindClusterHTTP3Policy(tx, req.NodeClusterId, nil)
	if err != nil {
		return nil, err
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return &pb.FindNodeClusterHTTP3PolicyResponse{
		Http3PolicyJSON: policyJSON,
	}, nil
}

// FindNodeClusterNetworkSecurityPolicy 获取集群的网络安全策略
func (this *NodeClusterService) FindNodeClusterNetworkSecurityPolicy(ctx context.Context, req *pb.FindNodeClusterNetworkSecurityPolicyRequest) (*pb.FindNodeClusterNetworkSecurityPolicyResponse, error) {
	return nil, this.NotImplementedYet()
}

// UpdateNodeClusterNetworkSecurityPolicy 修改集群的网络安全策略
func (this *NodeClusterService) UpdateNodeClusterNetworkSecurityPolicy(ctx context.Context, req *pb.UpdateNodeClusterNetworkSecurityPolicyRequest) (*pb.RPCSuccess, error) {
	return nil, this.NotImplementedYet()
}
