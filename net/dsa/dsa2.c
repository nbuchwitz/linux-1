// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * net/dsa/dsa2.c - Hardware switch handling, binding version 2
 * Copyright (c) 2008-2009 Marvell Semiconductor
 * Copyright (c) 2013 Florian Fainelli <florian@openwrt.org>
 * Copyright (c) 2016 Andrew Lunn <andrew@lunn.ch>
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/rtnetlink.h>
#include <linux/of.h>
#include <linux/of_net.h>
#include <net/devlink.h>

#include "dsa_priv.h"

static DEFINE_MUTEX(dsa2_mutex);
LIST_HEAD(dsa_tree_list);

struct dsa_switch *dsa_switch_find(int tree_index, int sw_index)
{
	struct dsa_switch_tree *dst;
	struct dsa_port *dp;

	list_for_each_entry(dst, &dsa_tree_list, list) {
		if (dst->index != tree_index)
			continue;

		list_for_each_entry(dp, &dst->ports, list) {
			if (dp->ds->index != sw_index)
				continue;

			return dp->ds;
		}
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(dsa_switch_find);

static struct dsa_switch_tree *dsa_tree_find(int index)
{
	struct dsa_switch_tree *dst;

	list_for_each_entry(dst, &dsa_tree_list, list)
		if (dst->index == index)
			return dst;

	return NULL;
}

static struct dsa_switch_tree *dsa_tree_alloc(int index)
{
	struct dsa_switch_tree *dst;

	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return NULL;

	dst->index = index;

	INIT_LIST_HEAD(&dst->rtable);

	INIT_LIST_HEAD(&dst->ports);

	INIT_LIST_HEAD(&dst->list);
	list_add_tail(&dst->list, &dsa_tree_list);

	kref_init(&dst->refcount);

	return dst;
}

static void dsa_tree_free(struct dsa_switch_tree *dst)
{
	list_del(&dst->list);
	kfree(dst);
}

static struct dsa_switch_tree *dsa_tree_get(struct dsa_switch_tree *dst)
{
	if (dst)
		kref_get(&dst->refcount);

	return dst;
}

static struct dsa_switch_tree *dsa_tree_touch(int index)
{
	struct dsa_switch_tree *dst;

	dst = dsa_tree_find(index);
	if (dst)
		return dsa_tree_get(dst);
	else
		return dsa_tree_alloc(index);
}

static void dsa_tree_release(struct kref *ref)
{
	struct dsa_switch_tree *dst;

	dst = container_of(ref, struct dsa_switch_tree, refcount);

	dsa_tree_free(dst);
}

static void dsa_tree_put(struct dsa_switch_tree *dst)
{
	if (dst)
		kref_put(&dst->refcount, dsa_tree_release);
}

static bool dsa_port_is_dsa(struct dsa_port *port)
{
	return port->type == DSA_PORT_TYPE_DSA;
}

static bool dsa_port_is_cpu(struct dsa_port *port)
{
	return port->type == DSA_PORT_TYPE_CPU;
}

static bool dsa_port_is_user(struct dsa_port *dp)
{
	return dp->type == DSA_PORT_TYPE_USER;
}

static struct dsa_port *dsa_tree_find_port_by_node(struct dsa_switch_tree *dst,
						   struct device_node *dn)
{
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		if (dp->dn == dn)
			return dp;

	return NULL;
}

static struct dsa_link *dsa_link_touch(struct dsa_port *dp,
				       struct dsa_port *link_dp)
{
	struct dsa_switch *ds = dp->ds;
	struct dsa_switch_tree *dst;
	struct dsa_link *dl;

	dst = ds->dst;

	list_for_each_entry(dl, &dst->rtable, list)
		if (dl->dp == dp && dl->link_dp == link_dp)
			return dl;

	dl = kzalloc(sizeof(*dl), GFP_KERNEL);
	if (!dl)
		return NULL;

	dl->dp = dp;
	dl->link_dp = link_dp;

	INIT_LIST_HEAD(&dl->list);
	list_add_tail(&dl->list, &dst->rtable);

	return dl;
}

static bool dsa_port_setup_routing_table(struct dsa_port *dp)
{
	struct dsa_switch *ds = dp->ds;
	struct dsa_switch_tree *dst = ds->dst;
	struct device_node *dn = dp->dn;
	struct of_phandle_iterator it;
	struct dsa_port *link_dp;
	struct dsa_link *dl;
	int err;

	of_for_each_phandle(&it, err, dn, "link", NULL, 0) {
		link_dp = dsa_tree_find_port_by_node(dst, it.node);
		if (!link_dp) {
			of_node_put(it.node);
			return false;
		}

		dl = dsa_link_touch(dp, link_dp);
		if (!dl) {
			of_node_put(it.node);
			return false;
		}
	}

	return true;
}

static bool dsa_tree_setup_routing_table(struct dsa_switch_tree *dst)
{
	bool complete = true;
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list) {
		if (dsa_port_is_dsa(dp)) {
			complete = dsa_port_setup_routing_table(dp);
			if (!complete)
				break;
		}
	}

	return complete;
}

static struct dsa_port *dsa_tree_find_first_cpu(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		if (dsa_port_is_cpu(dp))
			return dp;

	return NULL;
}

static int dsa_tree_setup_default_cpu(struct dsa_switch_tree *dst)
{
	struct dsa_port *cpu_dp, *dp;

	cpu_dp = dsa_tree_find_first_cpu(dst);
	if (!cpu_dp) {
		pr_err("DSA: tree %d has no CPU port\n", dst->index);
		return -EINVAL;
	}

	/* Assign the default CPU port to all ports of the fabric */
	list_for_each_entry(dp, &dst->ports, list)
		if (dsa_port_is_user(dp) || dsa_port_is_dsa(dp))
			dp->cpu_dp = cpu_dp;

	return 0;
}

static void dsa_tree_teardown_default_cpu(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		if (dsa_port_is_user(dp) || dsa_port_is_dsa(dp))
			dp->cpu_dp = NULL;
}

static int dsa_port_setup(struct dsa_port *dp)
{
	struct devlink_port *dlp = &dp->devlink_port;
	bool dsa_port_link_registered = false;
	bool dsa_port_enabled = false;
	int err = 0;

	if (dp->setup)
		return 0;

	switch (dp->type) {
	case DSA_PORT_TYPE_UNUSED:
		dsa_port_disable(dp);
		break;
	case DSA_PORT_TYPE_CPU:
		err = dsa_port_link_register_of(dp);
		if (err)
			break;
		dsa_port_link_registered = true;

		err = dsa_port_enable(dp, NULL);
		if (err)
			break;
		dsa_port_enabled = true;

		break;
	case DSA_PORT_TYPE_DSA:
		err = dsa_port_link_register_of(dp);
		if (err)
			break;
		dsa_port_link_registered = true;

		err = dsa_port_enable(dp, NULL);
		if (err)
			break;
		dsa_port_enabled = true;

		break;
	case DSA_PORT_TYPE_USER:
		dp->mac = of_get_mac_address(dp->dn);
		err = dsa_slave_create(dp);
		if (err)
			break;

		devlink_port_type_eth_set(dlp, dp->slave);
		break;
	}

	if (err && dsa_port_enabled)
		dsa_port_disable(dp);
	if (err && dsa_port_link_registered)
		dsa_port_link_unregister_of(dp);
	if (err)
		return err;

	dp->setup = true;

	return 0;
}

static int dsa_port_devlink_setup(struct dsa_port *dp)
{
	struct devlink_port *dlp = &dp->devlink_port;
	struct dsa_switch_tree *dst = dp->ds->dst;
	struct devlink_port_attrs attrs = {};
	struct devlink *dl = dp->ds->devlink;
	const unsigned char *id;
	unsigned char len;
	int err;

	id = (const unsigned char *)&dst->index;
	len = sizeof(dst->index);

	attrs.phys.port_number = dp->index;
	memcpy(attrs.switch_id.id, id, len);
	attrs.switch_id.id_len = len;
	memset(dlp, 0, sizeof(*dlp));

	switch (dp->type) {
	case DSA_PORT_TYPE_UNUSED:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_UNUSED;
		break;
	case DSA_PORT_TYPE_CPU:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_CPU;
		break;
	case DSA_PORT_TYPE_DSA:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_DSA;
		break;
	case DSA_PORT_TYPE_USER:
		attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
		break;
	}

	devlink_port_attrs_set(dlp, &attrs);
	err = devlink_port_register(dl, dlp, dp->index);

	if (!err)
		dp->devlink_port_setup = true;

	return err;
}

static void dsa_port_teardown(struct dsa_port *dp)
{
	struct devlink_port *dlp = &dp->devlink_port;

	if (!dp->setup)
		return;

	devlink_port_type_clear(dlp);

	switch (dp->type) {
	case DSA_PORT_TYPE_UNUSED:
		break;
	case DSA_PORT_TYPE_CPU:
		dsa_port_disable(dp);
		dsa_tag_driver_put(dp->tag_ops);
		dsa_port_link_unregister_of(dp);
		break;
	case DSA_PORT_TYPE_DSA:
		dsa_port_disable(dp);
		dsa_port_link_unregister_of(dp);
		break;
	case DSA_PORT_TYPE_USER:
		if (dp->slave) {
			dsa_slave_destroy(dp->slave);
			dp->slave = NULL;
		}
		break;
	}

	dp->setup = false;
}

static void dsa_port_devlink_teardown(struct dsa_port *dp)
{
	struct devlink_port *dlp = &dp->devlink_port;

	if (dp->devlink_port_setup)
		devlink_port_unregister(dlp);
	dp->devlink_port_setup = false;
}

static int dsa_devlink_info_get(struct devlink *dl,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct dsa_switch *ds = dsa_devlink_to_ds(dl);

	if (ds->ops->devlink_info_get)
		return ds->ops->devlink_info_get(ds, req, extack);

	return -EOPNOTSUPP;
}

static const struct devlink_ops dsa_devlink_ops = {
	.info_get = dsa_devlink_info_get,
};

static int dsa_switch_setup(struct dsa_switch *ds)
{
	struct dsa_devlink_priv *dl_priv;
	struct dsa_port *dp;
	int err;

	if (ds->setup)
		return 0;

	/* Initialize ds->phys_mii_mask before registering the slave MDIO bus
	 * driver and before ops->setup() has run, since the switch drivers and
	 * the slave MDIO bus driver rely on these values for probing PHY
	 * devices or not
	 */
	ds->phys_mii_mask |= dsa_user_ports(ds);

	/* Add the switch to devlink before calling setup, so that setup can
	 * add dpipe tables
	 */
	ds->devlink = devlink_alloc(&dsa_devlink_ops, sizeof(*dl_priv));
	if (!ds->devlink)
		return -ENOMEM;
	dl_priv = devlink_priv(ds->devlink);
	dl_priv->ds = ds;

	err = devlink_register(ds->devlink, ds->dev);
	if (err)
		goto free_devlink;

	/* Setup devlink port instances now, so that the switch
	 * setup() can register regions etc, against the ports
	 */
	list_for_each_entry(dp, &ds->dst->ports, list) {
		if (dp->ds == ds) {
			err = dsa_port_devlink_setup(dp);
			if (err)
				goto unregister_devlink_ports;
		}
	}

	err = dsa_switch_register_notifier(ds);
	if (err)
		goto unregister_devlink_ports;

	err = ds->ops->setup(ds);
	if (err < 0)
		goto unregister_notifier;

	devlink_params_publish(ds->devlink);

	if (!ds->slave_mii_bus && ds->ops->phy_read) {
		ds->slave_mii_bus = mdiobus_alloc();
		if (!ds->slave_mii_bus) {
			err = -ENOMEM;
			goto teardown;
		}

		dsa_slave_mii_bus_init(ds);

		err = mdiobus_register(ds->slave_mii_bus);
		if (err < 0)
			goto free_slave_mii_bus;
	}

	ds->setup = true;

	return 0;

free_slave_mii_bus:
	if (ds->slave_mii_bus && ds->ops->phy_read)
		mdiobus_free(ds->slave_mii_bus);
teardown:
	if (ds->ops->teardown)
		ds->ops->teardown(ds);
unregister_notifier:
	dsa_switch_unregister_notifier(ds);
unregister_devlink_ports:
	list_for_each_entry(dp, &ds->dst->ports, list)
		if (dp->ds == ds)
			dsa_port_devlink_teardown(dp);
	devlink_unregister(ds->devlink);
free_devlink:
	devlink_free(ds->devlink);
	ds->devlink = NULL;

	return err;
}

static void dsa_switch_teardown(struct dsa_switch *ds)
{
	struct dsa_port *dp;

	if (!ds->setup)
		return;

	if (ds->slave_mii_bus && ds->ops->phy_read) {
		mdiobus_unregister(ds->slave_mii_bus);
		mdiobus_free(ds->slave_mii_bus);
		ds->slave_mii_bus = NULL;
	}

	dsa_switch_unregister_notifier(ds);

	if (ds->ops->teardown)
		ds->ops->teardown(ds);

	if (ds->devlink) {
		list_for_each_entry(dp, &ds->dst->ports, list)
			if (dp->ds == ds)
				dsa_port_devlink_teardown(dp);
		devlink_unregister(ds->devlink);
		devlink_free(ds->devlink);
		ds->devlink = NULL;
	}

	ds->setup = false;
}

static int dsa_tree_setup_switches(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;
	int err;

	list_for_each_entry(dp, &dst->ports, list) {
		err = dsa_switch_setup(dp->ds);
		if (err)
			goto teardown;
	}

	list_for_each_entry(dp, &dst->ports, list) {
		err = dsa_port_setup(dp);
		if (err) {
			dsa_port_devlink_teardown(dp);
			dp->type = DSA_PORT_TYPE_UNUSED;
			err = dsa_port_devlink_setup(dp);
			if (err)
				goto teardown;
			continue;
		}
	}

	return 0;

teardown:
	list_for_each_entry(dp, &dst->ports, list)
		dsa_port_teardown(dp);

	list_for_each_entry(dp, &dst->ports, list)
		dsa_switch_teardown(dp->ds);

	return err;
}

static void dsa_tree_teardown_switches(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		dsa_port_teardown(dp);

	list_for_each_entry(dp, &dst->ports, list)
		dsa_switch_teardown(dp->ds);
}

static int dsa_tree_setup_master(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;
	int err;

	list_for_each_entry(dp, &dst->ports, list) {
		if (dsa_port_is_cpu(dp)) {
			err = dsa_master_setup(dp->master, dp);
			if (err)
				return err;
		}
	}

	return 0;
}

static void dsa_tree_teardown_master(struct dsa_switch_tree *dst)
{
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		if (dsa_port_is_cpu(dp))
			dsa_master_teardown(dp->master);
}

static int dsa_tree_setup(struct dsa_switch_tree *dst)
{
	bool complete;
	int err;

	if (dst->setup) {
		pr_err("DSA: tree %d already setup! Disjoint trees?\n",
		       dst->index);
		return -EEXIST;
	}

	complete = dsa_tree_setup_routing_table(dst);
	if (!complete)
		return 0;

	err = dsa_tree_setup_default_cpu(dst);
	if (err)
		return err;

	err = dsa_tree_setup_switches(dst);
	if (err)
		goto teardown_default_cpu;

	err = dsa_tree_setup_master(dst);
	if (err)
		goto teardown_switches;

	dst->setup = true;

	pr_info("DSA: tree %d setup\n", dst->index);

	return 0;

teardown_switches:
	dsa_tree_teardown_switches(dst);
teardown_default_cpu:
	dsa_tree_teardown_default_cpu(dst);

	return err;
}

static void dsa_tree_teardown(struct dsa_switch_tree *dst)
{
	struct dsa_link *dl, *next;

	if (!dst->setup)
		return;

	dsa_tree_teardown_master(dst);

	dsa_tree_teardown_switches(dst);

	dsa_tree_teardown_default_cpu(dst);

	list_for_each_entry_safe(dl, next, &dst->rtable, list) {
		list_del(&dl->list);
		kfree(dl);
	}

	pr_info("DSA: tree %d torn down\n", dst->index);

	dst->setup = false;
}

static struct dsa_port *dsa_port_touch(struct dsa_switch *ds, int index)
{
	struct dsa_switch_tree *dst = ds->dst;
	struct dsa_port *dp;

	list_for_each_entry(dp, &dst->ports, list)
		if (dp->ds == ds && dp->index == index)
			return dp;

	dp = kzalloc(sizeof(*dp), GFP_KERNEL);
	if (!dp)
		return NULL;

	dp->ds = ds;
	dp->index = index;

	INIT_LIST_HEAD(&dp->list);
	list_add_tail(&dp->list, &dst->ports);

	return dp;
}

static int dsa_port_parse_user(struct dsa_port *dp, const char *name)
{
	if (!name)
		name = "eth%d";

	dp->type = DSA_PORT_TYPE_USER;
	dp->name = name;

	return 0;
}

static int dsa_port_parse_dsa(struct dsa_port *dp)
{
	dp->type = DSA_PORT_TYPE_DSA;

	return 0;
}

static enum dsa_tag_protocol dsa_get_tag_protocol(struct dsa_port *dp,
						  struct net_device *master)
{
	enum dsa_tag_protocol tag_protocol = DSA_TAG_PROTO_NONE;
	struct dsa_switch *mds, *ds = dp->ds;
	unsigned int mdp_upstream;
	struct dsa_port *mdp;

	/* It is possible to stack DSA switches onto one another when that
	 * happens the switch driver may want to know if its tagging protocol
	 * is going to work in such a configuration.
	 */
	if (dsa_slave_dev_check(master)) {
		mdp = dsa_slave_to_port(master);
		mds = mdp->ds;
		mdp_upstream = dsa_upstream_port(mds, mdp->index);
		tag_protocol = mds->ops->get_tag_protocol(mds, mdp_upstream,
							  DSA_TAG_PROTO_NONE);
	}

	/* If the master device is not itself a DSA slave in a disjoint DSA
	 * tree, then return immediately.
	 */
	return ds->ops->get_tag_protocol(ds, dp->index, tag_protocol);
}

static int dsa_port_parse_cpu(struct dsa_port *dp, struct net_device *master)
{
	struct dsa_switch *ds = dp->ds;
	struct dsa_switch_tree *dst = ds->dst;
	const struct dsa_device_ops *tag_ops;
	enum dsa_tag_protocol tag_protocol;

	tag_protocol = dsa_get_tag_protocol(dp, master);
	tag_ops = dsa_tag_driver_get(tag_protocol);
	if (IS_ERR(tag_ops)) {
		if (PTR_ERR(tag_ops) == -ENOPROTOOPT)
			return -EPROBE_DEFER;
		dev_warn(ds->dev, "No tagger for this switch\n");
		dp->master = NULL;
		return PTR_ERR(tag_ops);
	}

	dp->master = master;
	dp->type = DSA_PORT_TYPE_CPU;
	dp->filter = tag_ops->filter;
	dp->rcv = tag_ops->rcv;
	dp->tag_ops = tag_ops;
	dp->dst = dst;

	return 0;
}

static int dsa_port_parse_of(struct dsa_port *dp, struct device_node *dn)
{
	struct device_node *ethernet = of_parse_phandle(dn, "ethernet", 0);
	const char *name = of_get_property(dn, "label", NULL);
	bool link = of_property_read_bool(dn, "link");

	dp->dn = dn;

	if (ethernet) {
		struct net_device *master;

		master = of_find_net_device_by_node(ethernet);
		of_node_put(ethernet);
		if (!master)
			return -EPROBE_DEFER;

		return dsa_port_parse_cpu(dp, master);
	}

	if (link)
		return dsa_port_parse_dsa(dp);

	return dsa_port_parse_user(dp, name);
}

static int dsa_switch_parse_ports_of(struct dsa_switch *ds,
				     struct device_node *dn)
{
	struct device_node *ports, *port;
	struct dsa_port *dp;
	int err = 0;
	u32 reg;

	ports = of_get_child_by_name(dn, "ports");
	if (!ports) {
		/* The second possibility is "ethernet-ports" */
		ports = of_get_child_by_name(dn, "ethernet-ports");
		if (!ports) {
			dev_err(ds->dev, "no ports child node found\n");
			return -EINVAL;
		}
	}

	for_each_available_child_of_node(ports, port) {
		err = of_property_read_u32(port, "reg", &reg);
		if (err)
			goto out_put_node;

		if (reg >= ds->num_ports) {
			err = -EINVAL;
			goto out_put_node;
		}

		dp = dsa_to_port(ds, reg);

		err = dsa_port_parse_of(dp, port);
		if (err)
			goto out_put_node;
	}

out_put_node:
	of_node_put(ports);
	return err;
}

static int dsa_switch_parse_member_of(struct dsa_switch *ds,
				      struct device_node *dn)
{
	u32 m[2] = { 0, 0 };
	int sz;

	/* Don't error out if this optional property isn't found */
	sz = of_property_read_variable_u32_array(dn, "dsa,member", m, 2, 2);
	if (sz < 0 && sz != -EINVAL)
		return sz;

	ds->index = m[1];

	ds->dst = dsa_tree_touch(m[0]);
	if (!ds->dst)
		return -ENOMEM;

	return 0;
}

static int dsa_switch_touch_ports(struct dsa_switch *ds)
{
	struct dsa_port *dp;
	int port;

	for (port = 0; port < ds->num_ports; port++) {
		dp = dsa_port_touch(ds, port);
		if (!dp)
			return -ENOMEM;
	}

	return 0;
}

static int dsa_switch_parse_of(struct dsa_switch *ds, struct device_node *dn)
{
	int err;

	err = dsa_switch_parse_member_of(ds, dn);
	if (err)
		return err;

	err = dsa_switch_touch_ports(ds);
	if (err)
		return err;

	return dsa_switch_parse_ports_of(ds, dn);
}

static int dsa_port_parse(struct dsa_port *dp, const char *name,
			  struct device *dev)
{
	if (!strcmp(name, "cpu")) {
		struct net_device *master;

		master = dsa_dev_to_net_device(dev);
		if (!master)
			return -EPROBE_DEFER;

		dev_put(master);

		return dsa_port_parse_cpu(dp, master);
	}

	if (!strcmp(name, "dsa"))
		return dsa_port_parse_dsa(dp);

	return dsa_port_parse_user(dp, name);
}

static int dsa_switch_parse_ports(struct dsa_switch *ds,
				  struct dsa_chip_data *cd)
{
	bool valid_name_found = false;
	struct dsa_port *dp;
	struct device *dev;
	const char *name;
	unsigned int i;
	int err;

	for (i = 0; i < DSA_MAX_PORTS; i++) {
		name = cd->port_names[i];
		dev = cd->netdev[i];
		dp = dsa_to_port(ds, i);

		if (!name)
			continue;

		err = dsa_port_parse(dp, name, dev);
		if (err)
			return err;

		valid_name_found = true;
	}

	if (!valid_name_found && i == DSA_MAX_PORTS)
		return -EINVAL;

	return 0;
}

static int dsa_switch_parse(struct dsa_switch *ds, struct dsa_chip_data *cd)
{
	int err;

	ds->cd = cd;

	/* We don't support interconnected switches nor multiple trees via
	 * platform data, so this is the unique switch of the tree.
	 */
	ds->index = 0;
	ds->dst = dsa_tree_touch(0);
	if (!ds->dst)
		return -ENOMEM;

	err = dsa_switch_touch_ports(ds);
	if (err)
		return err;

	return dsa_switch_parse_ports(ds, cd);
}

static void dsa_switch_release_ports(struct dsa_switch *ds)
{
	struct dsa_switch_tree *dst = ds->dst;
	struct dsa_port *dp, *next;

	list_for_each_entry_safe(dp, next, &dst->ports, list) {
		if (dp->ds != ds)
			continue;
		list_del(&dp->list);
		kfree(dp);
	}
}

static int dsa_switch_probe(struct dsa_switch *ds)
{
	struct dsa_switch_tree *dst;
	struct dsa_chip_data *pdata;
	struct device_node *np;
	int err;

	if (!ds->dev)
		return -ENODEV;

	pdata = ds->dev->platform_data;
	np = ds->dev->of_node;

	if (!ds->num_ports)
		return -EINVAL;

	if (np) {
		err = dsa_switch_parse_of(ds, np);
		if (err)
			dsa_switch_release_ports(ds);
	} else if (pdata) {
		err = dsa_switch_parse(ds, pdata);
		if (err)
			dsa_switch_release_ports(ds);
	} else {
		err = -ENODEV;
	}

	if (err)
		return err;

	dst = ds->dst;
	dsa_tree_get(dst);
	err = dsa_tree_setup(dst);
	if (err) {
		dsa_switch_release_ports(ds);
		dsa_tree_put(dst);
	}

	return err;
}

int dsa_register_switch(struct dsa_switch *ds)
{
	int err;

	mutex_lock(&dsa2_mutex);
	err = dsa_switch_probe(ds);
	dsa_tree_put(ds->dst);
	mutex_unlock(&dsa2_mutex);

	return err;
}
EXPORT_SYMBOL_GPL(dsa_register_switch);

static void dsa_switch_remove(struct dsa_switch *ds)
{
	struct dsa_switch_tree *dst = ds->dst;

	dsa_tree_teardown(dst);
	dsa_switch_release_ports(ds);
	dsa_tree_put(dst);
}

void dsa_unregister_switch(struct dsa_switch *ds)
{
	mutex_lock(&dsa2_mutex);
	dsa_switch_remove(ds);
	mutex_unlock(&dsa2_mutex);
}
EXPORT_SYMBOL_GPL(dsa_unregister_switch);

/* If the DSA master chooses to unregister its net_device on .shutdown, DSA is
 * blocking that operation from completion, due to the dev_hold taken inside
 * netdev_upper_dev_link. Unlink the DSA slave interfaces from being uppers of
 * the DSA master, so that the system can reboot successfully.
 */
void dsa_switch_shutdown(struct dsa_switch *ds)
{
	struct net_device *master, *slave_dev;
	LIST_HEAD(unregister_list);
	struct dsa_port *dp;

	mutex_lock(&dsa2_mutex);
	rtnl_lock();

	list_for_each_entry(dp, &ds->dst->ports, list) {
		if (dp->ds != ds)
			continue;

		if (!dsa_port_is_user(dp))
			continue;

		master = dp->cpu_dp->master;
		slave_dev = dp->slave;

		netdev_upper_dev_unlink(master, slave_dev);
		/* Just unlinking ourselves as uppers of the master is not
		 * sufficient. When the master net device unregisters, that will
		 * also call dev_close, which we will catch as NETDEV_GOING_DOWN
		 * and trigger a dev_close on our own devices (dsa_slave_close).
		 * In turn, that will call dev_mc_unsync on the master's net
		 * device. If the master is also a DSA switch port, this will
		 * trigger dsa_slave_set_rx_mode which will call dev_mc_sync on
		 * its own master. Lockdep will complain about the fact that
		 * all cascaded masters have the same dsa_master_addr_list_lock_key,
		 * which it normally would not do if the cascaded masters would
		 * be in a proper upper/lower relationship, which we've just
		 * destroyed.
		 * To suppress the lockdep warnings, let's actually unregister
		 * the DSA slave interfaces too, to avoid the nonsensical
		 * multicast address list synchronization on shutdown.
		 */
		unregister_netdevice_queue(slave_dev, &unregister_list);
	}
	unregister_netdevice_many(&unregister_list);

	rtnl_unlock();
	mutex_unlock(&dsa2_mutex);
}
EXPORT_SYMBOL_GPL(dsa_switch_shutdown);
