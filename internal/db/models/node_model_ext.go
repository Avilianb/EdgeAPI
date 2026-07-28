package models

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/TeaOSLab/EdgeAPI/internal/remotelogs"
	"github.com/TeaOSLab/EdgeCommon/pkg/nodeconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/ddosconfigs"
	"github.com/TeaOSLab/EdgeCommon/pkg/serverconfigs/shared"
	timeutil "github.com/iwind/TeaGo/utils/time"
)

// DecodeInstallStatus 安装状态
func (this *Node) DecodeInstallStatus() (*NodeInstallStatus, error) {
	if len(this.InstallStatus) == 0 {
		return NewNodeInstallStatus(), nil
	}
	var status = &NodeInstallStatus{}
	err := json.Unmarshal(this.InstallStatus, status)
	if err != nil {
		return NewNodeInstallStatus(), err
	}

	// 如果N秒钟没有更新状态，则认为不在运行
	if status.IsRunning && status.UpdatedAt < time.Now().Unix()-10 {
		status.IsRunning = false
		status.IsFinished = true
		status.Error = "timeout"
	}

	return status, nil
}

// DecodeStatus 节点状态
func (this *Node) DecodeStatus() (*nodeconfigs.NodeStatus, error) {
	if len(this.Status) == 0 {
		return nil, nil
	}
	var status = &nodeconfigs.NodeStatus{}
	err := json.Unmarshal(this.Status, status)
	if err != nil {
		return nil, err
	}
	return status, nil
}

// NodeDNSRoutes 节点DNS线路配置。
//
// Legacy 兼容旧版本的 {domainId: [routeCode]} 格式；Clusters 是新的
// {clusterId: {domainId: [routeCode]}} 格式。两者共存时，集群配置优先。
type NodeDNSRoutes struct {
	Legacy   map[int64][]string           `json:"legacy,omitempty"`
	Clusters map[int64]map[int64][]string `json:"clusters,omitempty"`
}

// DecodeDNSRoutes 解析节点DNS线路，同时兼容旧版数据格式。
func (this *Node) DecodeDNSRoutes() (*NodeDNSRoutes, error) {
	var config = &NodeDNSRoutes{
		Legacy:   map[int64][]string{},
		Clusters: map[int64]map[int64][]string{},
	}
	if len(this.DnsRoutes) == 0 {
		return config, nil
	}

	var raw = map[string]json.RawMessage{}
	err := json.Unmarshal(this.DnsRoutes, &raw)
	if err != nil {
		return nil, err
	}

	_, hasLegacy := raw["legacy"]
	_, hasClusters := raw["clusters"]
	if hasLegacy || hasClusters {
		err = json.Unmarshal(this.DnsRoutes, config)
		if err != nil {
			return nil, err
		}
		if config.Legacy == nil {
			config.Legacy = map[int64][]string{}
		}
		if config.Clusters == nil {
			config.Clusters = map[int64]map[int64][]string{}
		}
		return config, nil
	}

	// v1 格式：{domainId: [routeCode]}
	err = json.Unmarshal(this.DnsRoutes, &config.Legacy)
	if err != nil {
		return nil, err
	}
	if config.Legacy == nil {
		config.Legacy = map[int64][]string{}
	}
	return config, nil
}

func cloneAndSortDNSRouteCodes(routeCodes []string) []string {
	if len(routeCodes) == 0 {
		return []string{}
	}
	var result = append([]string{}, routeCodes...)
	sort.Strings(result)
	return result
}

// DNSRouteCodes 所有的DNS线路。
//
// 此方法用于旧的汇总展示；按集群生成DNS记录时必须使用
// DNSRouteCodesForClusterId。
func (this *Node) DNSRouteCodes() map[int64][]string {
	config, err := this.DecodeDNSRoutes()
	if err != nil {
		return map[int64][]string{}
	}

	var result = map[int64][]string{}
	for domainId, routeCodes := range config.Legacy {
		result[domainId] = append(result[domainId], routeCodes...)
	}
	for _, clusterRoutes := range config.Clusters {
		for domainId, routeCodes := range clusterRoutes {
			for _, routeCode := range routeCodes {
				var found = false
				for _, oldRouteCode := range result[domainId] {
					if oldRouteCode == routeCode {
						found = true
						break
					}
				}
				if !found {
					result[domainId] = append(result[domainId], routeCode)
				}
			}
		}
	}
	for domainId, routeCodes := range result {
		result[domainId] = cloneAndSortDNSRouteCodes(routeCodes)
	}
	return result
}

// DNSRouteCodesForClusterId 返回某个集群、某个DNS域名对应的线路。
// 新配置不存在时回退到旧版共享配置，以保证升级后已有解析不受影响。
func (this *Node) DNSRouteCodesForClusterId(clusterId int64, dnsDomainId int64) ([]string, error) {
	config, err := this.DecodeDNSRoutes()
	if err != nil {
		return nil, err
	}

	if clusterRoutes, ok := config.Clusters[clusterId]; ok {
		if routeCodes, ok := clusterRoutes[dnsDomainId]; ok {
			return cloneAndSortDNSRouteCodes(routeCodes), nil
		}
	}
	return cloneAndSortDNSRouteCodes(config.Legacy[dnsDomainId]), nil
}

// DNSRouteCodesForDomainId 兼容旧调用。新的按集群逻辑请使用
// DNSRouteCodesForClusterId。
func (this *Node) DNSRouteCodesForDomainId(dnsDomainId int64) ([]string, error) {
	config, err := this.DecodeDNSRoutes()
	if err != nil {
		return nil, err
	}
	return cloneAndSortDNSRouteCodes(config.Legacy[dnsDomainId]), nil
}

// DecodeConnectedAPINodeIds 连接的API
func (this *Node) DecodeConnectedAPINodeIds() ([]int64, error) {
	var apiNodeIds = []int64{}
	if IsNotNull(this.ConnectedAPINodes) {
		err := json.Unmarshal(this.ConnectedAPINodes, &apiNodeIds)
		if err != nil {
			return nil, err
		}
	}
	return apiNodeIds, nil
}

// DecodeSecondaryClusterIds 从集群IDs
func (this *Node) DecodeSecondaryClusterIds() []int64 {
	if len(this.SecondaryClusterIds) == 0 {
		return []int64{}
	}
	var result = []int64{}
	// 不需要处理错误
	_ = json.Unmarshal(this.SecondaryClusterIds, &result)
	return result
}

// AllClusterIds 获取所属集群IDs
func (this *Node) AllClusterIds() []int64 {
	var result = []int64{}

	if this.ClusterId > 0 {
		result = append(result, int64(this.ClusterId))
	}

	result = append(result, this.DecodeSecondaryClusterIds()...)

	return result
}

// DecodeDDoSProtection 解析DDoS Protection设置
func (this *Node) DecodeDDoSProtection() *ddosconfigs.ProtectionConfig {
	if IsNull(this.DdosProtection) {
		return nil
	}

	var result = &ddosconfigs.ProtectionConfig{}
	err := json.Unmarshal(this.DdosProtection, &result)
	if err != nil {
		// ignore err
	}
	return result
}

// HasDDoSProtection 检查是否有DDOS设置
func (this *Node) HasDDoSProtection() bool {
	var config = this.DecodeDDoSProtection()
	if config != nil {
		return !config.IsPriorEmpty()
	}
	return false
}

// DecodeMaxCacheDiskCapacity 解析硬盘容量
func (this *Node) DecodeMaxCacheDiskCapacity() *shared.SizeCapacity {
	if this.MaxCacheDiskCapacity.IsNull() {
		return nil
	}

	// ignore error
	capacity, _ := shared.DecodeSizeCapacityJSON(this.MaxCacheDiskCapacity)
	return capacity
}

// DecodeMaxCacheMemoryCapacity 解析内存容量
func (this *Node) DecodeMaxCacheMemoryCapacity() *shared.SizeCapacity {
	if this.MaxCacheMemoryCapacity.IsNull() {
		return nil
	}

	// ignore error
	capacity, _ := shared.DecodeSizeCapacityJSON(this.MaxCacheMemoryCapacity)
	return capacity
}

// DecodeDNSResolver 解析DNS解析主机配置
func (this *Node) DecodeDNSResolver() *nodeconfigs.DNSResolverConfig {
	if this.DnsResolver.IsNull() {
		return nil
	}

	var resolverConfig = nodeconfigs.DefaultDNSResolverConfig()
	err := json.Unmarshal(this.DnsResolver, resolverConfig)
	if err != nil {
		// ignore error
	}
	return resolverConfig
}

// DecodeLnAddrs 解析Ln地址
func (this *Node) DecodeLnAddrs() []string {
	if IsNull(this.LnAddrs) {
		return nil
	}

	var result = []string{}
	err := json.Unmarshal(this.LnAddrs, &result)
	if err != nil {
		// ignore error
	}
	return result
}

// DecodeCacheDiskSubDirs 解析缓存目录
func (this *Node) DecodeCacheDiskSubDirs() []*serverconfigs.CacheDir {
	if IsNull(this.CacheDiskSubDirs) {
		return nil
	}

	var result = []*serverconfigs.CacheDir{}
	err := json.Unmarshal(this.CacheDiskSubDirs, &result)
	if err != nil {
		remotelogs.Error("Node.DecodeCacheDiskSubDirs", err.Error())
	}
	return result
}

// DecodeAPINodeAddrs 解析API节点地址
func (this *Node) DecodeAPINodeAddrs() []*serverconfigs.NetworkAddressConfig {
	var result = []*serverconfigs.NetworkAddressConfig{}
	if IsNull(this.ApiNodeAddrs) {
		return result
	}

	err := json.Unmarshal(this.ApiNodeAddrs, &result)
	if err != nil {
		remotelogs.Error("Node.DecodeAPINodeAddrs", err.Error())
	}
	return result
}

// CheckIsOffline 检查是否已经离线
func (this *Node) CheckIsOffline() bool {
	return len(this.OfflineDay) > 0 && this.OfflineDay < timeutil.Format("Ymd")
}
