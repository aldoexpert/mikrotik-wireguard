package library

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	externalip "github.com/glendc/go-external-ip"

	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

// SubnetRanges/SubnetRangesOrder are the named IP pools an admin can define
// via MTWG_SUBNET_RANGES, offered when suggesting an IP for a new client.
var (
	SubnetRanges      = map[string][]*net.IPNet{}
	SubnetRangesOrder []string
	ipToSubnetRange   = map[string]uint16{}
)

// ParseSubnetRanges parses "name1:cidr1,cidr2;name2:cidr3" into SubnetRanges.
func ParseSubnetRanges(subnetRangesStr string) map[string][]*net.IPNet {
	subnetRanges := map[string][]*net.IPNet{}
	SubnetRangesOrder = nil
	if subnetRangesStr == "" {
		return subnetRanges
	}

	cidrSet := map[string]bool{}
	subnetRangesStr = strings.TrimSpace(subnetRangesStr)
	subnetRangesStr = strings.Trim(subnetRangesStr, ";:,")
	for _, rng := range strings.Split(subnetRangesStr, ";") {
		rng = strings.TrimSpace(rng)
		rngSpl := strings.Split(rng, ":")
		if len(rngSpl) != 2 {
			log.Printf("[WARNING] Unable to parse subnet range: %v. Skipped.", rng)
			continue
		}
		rngName := strings.TrimSpace(rngSpl[0])
		subnetRanges[rngName] = make([]*net.IPNet, 0)
		for _, cidr := range strings.Split(rngSpl[1], ",") {
			cidr = strings.TrimSpace(cidr)
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("[WARNING] [%v] Unable to parse CIDR: %v. Skipped.", rngName, cidr)
				continue
			}
			if cidrSet[n.String()] {
				continue
			}
			cidrSet[n.String()] = true
			subnetRanges[rngName] = append(subnetRanges[rngName], n)
		}
		if len(subnetRanges[rngName]) == 0 {
			delete(subnetRanges, rngName)
		} else {
			SubnetRangesOrder = append(SubnetRangesOrder, rngName)
		}
	}
	SubnetRanges = subnetRanges
	return subnetRanges
}

// GetSubnetRangesString returns a human readable summary of active ranges.
func GetSubnetRangesString() string {
	if len(SubnetRangesOrder) == 0 {
		return ""
	}
	var b strings.Builder
	for _, rng := range SubnetRangesOrder {
		cidrs := SubnetRanges[rng]
		if len(cidrs) == 0 {
			continue
		}
		b.WriteString(rng)
		b.WriteString(":[")
		for i, cidr := range cidrs {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(cidr.String())
		}
		b.WriteString("]  ")
	}
	return strings.TrimSpace(b.String())
}

// ValidateAndFixSubnetRanges drops any configured CIDR that does not belong
// to one of the server's own interface addresses.
func ValidateAndFixSubnetRanges(db store.IStore) error {
	if len(SubnetRangesOrder) == 0 {
		return nil
	}

	server, err := db.GetServer()
	if err != nil {
		return err
	}

	var serverSubnets []*net.IPNet
	for _, addr := range server.Interface.Addresses {
		_, netAddr, err := net.ParseCIDR(strings.TrimSpace(addr))
		if err != nil {
			return err
		}
		serverSubnets = append(serverSubnets, netAddr)
	}

	for _, rng := range SubnetRangesOrder {
		cidrs := SubnetRanges[rng]
		newCIDRs := make([]*net.IPNet, 0, len(cidrs))
		for _, cidr := range cidrs {
			valid := false
			for _, serverSubnet := range serverSubnets {
				if ContainsCIDR(serverSubnet, cidr) {
					valid = true
					break
				}
			}
			if valid {
				newCIDRs = append(newCIDRs, cidr)
			} else {
				log.Printf("[WARNING] [%v] CIDR is outside of all server subnets: %v. Removed.", rng, cidr)
			}
		}
		if len(newCIDRs) > 0 {
			SubnetRanges[rng] = newCIDRs
		} else {
			delete(SubnetRanges, rng)
			log.Printf("[WARNING] [%v] No valid CIDRs in this subnet range. Removed.", rng)
		}
	}

	return nil
}

// ContainsCIDR reports whether ipnet1 fully contains ipnet2.
func ContainsCIDR(ipnet1, ipnet2 *net.IPNet) bool {
	ones1, _ := ipnet1.Mask.Size()
	ones2, _ := ipnet2.Mask.Size()
	return ones1 <= ones2 && ipnet1.Contains(ipnet2.IP)
}

func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func ValidateCIDRList(cidrs []string, allowEmpty bool) bool {
	for _, cidr := range cidrs {
		if allowEmpty && cidr == "" {
			continue
		}
		if !ValidateCIDR(cidr) {
			return false
		}
	}
	return true
}

func ValidateAllowedIPs(cidrs []string) bool      { return ValidateCIDRList(cidrs, false) }
func ValidateExtraAllowedIPs(cidrs []string) bool { return ValidateCIDRList(cidrs, true) }
func ValidateServerAddresses(cidrs []string) bool { return ValidateCIDRList(cidrs, false) }

func ValidateIPAddress(ip string) bool { return net.ParseIP(ip) != nil }

func ValidateIPAddressList(ips []string) bool {
	for _, ip := range ips {
		if !ValidateIPAddress(ip) {
			return false
		}
	}
	return true
}

// GetInterfaceIPs returns this machine's own (non-loopback, IPv4) interface
// addresses -- used to help an admin pick an endpoint address.
func GetInterfaceIPs() ([]model.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var list []model.Interface
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			list = append(list, model.Interface{Name: i.Name, IPAddress: ip.String()})
		}
	}
	return list, nil
}

// GetPublicIP asks a few trusted external services for this machine's
// public IP address.
func GetPublicIP() (model.Interface, error) {
	cfg := externalip.ConsensusConfig{Timeout: 5 * time.Second}
	consensus := externalip.NewConsensus(&cfg, nil)
	consensus.AddVoter(externalip.NewHTTPSource("https://checkip.amazonaws.com/"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("http://whatismyip.akamai.com"), 1)
	consensus.AddVoter(externalip.NewHTTPSource("https://ifconfig.top"), 1)

	iface := model.Interface{Name: "Public Address"}
	ip, err := consensus.ExternalIP()
	if err != nil {
		iface.IPAddress = "N/A"
	} else {
		iface.IPAddress = ip.String()
	}
	return iface, nil
}

func GetIPFromCIDR(cidr string) (string, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

// GetAllocatedIPs collects every IP already in use (server + all clients
// except ignoreClientID) by reading through the store, instead of opening a
// second, hardcoded connection to the database directory.
func GetAllocatedIPs(db store.IStore, ignoreClientID string) ([]string, error) {
	allocated := make([]string, 0)

	server, err := db.GetServer()
	if err != nil {
		return nil, err
	}
	for _, cidr := range server.Interface.Addresses {
		ip, err := GetIPFromCIDR(cidr)
		if err != nil {
			return nil, err
		}
		allocated = append(allocated, ip)
	}

	clients, err := db.GetClients(false)
	if err != nil {
		return nil, err
	}
	for _, cd := range clients {
		if cd.Client == nil || cd.Client.ID == ignoreClientID {
			continue
		}
		for _, cidr := range cd.Client.AllocatedIPs {
			ip, err := GetIPFromCIDR(cidr)
			if err != nil {
				return nil, err
			}
			allocated = append(allocated, ip)
		}
	}

	return allocated, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// GetBroadcastIP returns the broadcast address of network n.
func GetBroadcastIP(n *net.IPNet) net.IP {
	var broadcast net.IP
	if len(n.IP) == 4 {
		broadcast = net.ParseIP("0.0.0.0").To4()
	} else {
		broadcast = net.ParseIP("::")
	}
	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

// GetBroadcastAndNetworkAddrsLookup returns the set of addresses that can't
// be assigned to a client (network + broadcast address of each interface).
func GetBroadcastAndNetworkAddrsLookup(interfaceAddresses []string) map[string]bool {
	list := make(map[string]bool)
	for _, ifa := range interfaceAddresses {
		_, netAddr, err := net.ParseCIDR(ifa)
		if err != nil {
			continue
		}
		list[GetBroadcastIP(netAddr).String()] = true
		list[netAddr.IP.String()] = true
	}
	return list
}

// GetAvailableIP returns the first unallocated address inside cidr.
func GetAvailableIP(cidr string, allocatedList, interfaceAddresses []string) (string, error) {
	ip, netAddr, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	unavailable := GetBroadcastAndNetworkAddrsLookup(interfaceAddresses)

	for ip := ip.Mask(netAddr.Mask); netAddr.Contains(ip); incIP(ip) {
		suggested := ip.String()
		available := !unavailable[suggested]
		if available {
			for _, a := range allocatedList {
				if a == suggested {
					available = false
					break
				}
			}
		}
		if available {
			return suggested, nil
		}
	}

	return "", errors.New("no more available ip address")
}

// ValidateIPAllocation checks that every CIDR in ipAllocationList is
// correctly formatted, not already allocated, and inside serverAddresses.
func ValidateIPAllocation(serverAddresses, ipAllocatedList, ipAllocationList []string) (bool, error) {
	for _, clientCIDR := range ipAllocationList {
		ip, _, _ := net.ParseCIDR(clientCIDR)
		if ip == nil {
			return false, fmt.Errorf("invalid ip allocation input %s. Must be in CIDR format", clientCIDR)
		}

		for _, item := range ipAllocatedList {
			if item == ip.String() {
				return false, fmt.Errorf("IP %s already allocated", ip)
			}
		}

		valid := false
		for _, serverCIDR := range serverAddresses {
			_, serverNet, _ := net.ParseCIDR(serverCIDR)
			if serverNet != nil && serverNet.Contains(ip) {
				valid = true
				break
			}
		}
		if !valid {
			return false, fmt.Errorf("IP %s does not belong to any network addresses of the WireGuard server", ip)
		}
	}

	return true, nil
}

func findSubnetRangeForIP(cidr string) (uint16, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, err
	}

	if idx, ok := ipToSubnetRange[ip.String()]; ok {
		return idx, nil
	}

	for idx, sr := range SubnetRangesOrder {
		for _, srCIDR := range SubnetRanges[sr] {
			if srCIDR.Contains(ip) {
				ipToSubnetRange[ip.String()] = uint16(idx)
				return uint16(idx), nil
			}
		}
	}
	return 0, fmt.Errorf("subnet range not found for this IP")
}

// FillClientSubnetRange annotates a ClientData with the names of every
// subnet range its allocated IPs belong to.
func FillClientSubnetRange(client model.ClientData) model.ClientData {
	cl := *client.Client
	for _, ip := range cl.AllocatedIPs {
		idx, err := findSubnetRangeForIP(ip)
		if err != nil {
			continue
		}
		cl.SubnetRanges = append(cl.SubnetRanges, SubnetRangesOrder[idx])
	}
	return model.ClientData{Client: &cl, QRCode: client.QRCode}
}
