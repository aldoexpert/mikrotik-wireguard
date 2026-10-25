package jsondb

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

func (o *JsonDB) GetWakeOnLanHosts() ([]model.WakeOnLanHost, error) {
	var hosts []model.WakeOnLanHost

	records, err := o.conn.ReadAll(model.WakeOnLanHostCollectionName)
	if err != nil {
		return hosts, err
	}

	for _, f := range records {
		host := model.WakeOnLanHost{}
		if err := json.Unmarshal(f, &host); err != nil {
			return hosts, fmt.Errorf("cannot decode wake-on-lan host json structure: %v", err)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (o *JsonDB) GetWakeOnLanHost(macAddress string) (*model.WakeOnLanHost, error) {
	host := &model.WakeOnLanHost{MacAddress: macAddress}
	resourceName, err := host.ResolveResourceName()
	if err != nil {
		return nil, err
	}

	if err := o.conn.Read(model.WakeOnLanHostCollectionName, resourceName, host); err != nil {
		return nil, err
	}
	return host, nil
}

func (o *JsonDB) DeleteWakeOnHostLanHost(macAddress string) error {
	host := &model.WakeOnLanHost{MacAddress: macAddress}
	resourceName, err := host.ResolveResourceName()
	if err != nil {
		return err
	}
	return o.conn.Delete(model.WakeOnLanHostCollectionName, resourceName)
}

func (o *JsonDB) SaveWakeOnLanHost(host model.WakeOnLanHost) error {
	resourceName, err := host.ResolveResourceName()
	if err != nil {
		return err
	}

	p := path.Join(o.dbPath, model.WakeOnLanHostCollectionName, resourceName+".json")
	if err := o.conn.Write(model.WakeOnLanHostCollectionName, resourceName, host); err != nil {
		return err
	}
	return library.ManagePerms(p)
}

func (o *JsonDB) DeleteWakeOnHost(host model.WakeOnLanHost) error {
	resourceName, err := host.ResolveResourceName()
	if err != nil {
		return err
	}
	return o.conn.Delete(model.WakeOnLanHostCollectionName, resourceName)
}
