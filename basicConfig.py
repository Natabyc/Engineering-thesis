from panos import firewall

# firstly connect with the device - type in the correct credentials
fw = firewall.Firewall("10.74.1.16", "login", "password")


#assigning interfaces
from panos.network import EthernetInterface
eth1 = EthernetInterface(name="ethernet1/1",
                         mode="layer3",
                         ip=("192.168.3.1/24"))
fw.add(eth1)

eth3 = EthernetInterface(name="ethernet1/3",
                         mode="layer3",
                         ip=("192.168.4.1/24"))
fw.add(eth3)

eth4 = EthernetInterface(name="ethernet1/4",
                         mode="layer3",
                         ip=("192.168.5.1/24"))
fw.add(eth4)

eth4.create_similar()

# creating zones
from panos.network import Zone
lan = Zone(name="LAN",
            mode="layer3",
            interface="ethernet1/3")
fw.add(lan)

dmz = Zone(name="DMZ",
            mode="layer3",
            interface="ethernet1/4")
fw.add(dmz)

wan = Zone(name="WAN",
           mode="layer3",
           interface="ethernet1/1")
fw.add(wan)

wan.create_similar()


# configuring virtual router and static routes
from panos.network import VirtualRouter, StaticRoute
def_static_r1 = StaticRoute(name="to_WAN",
                           destination="192.168.3.0/24", 
                           nexthop_type="ip-address",
                           nexthop="192.168.3.1",
                           interface="ethernet1/1")

router = VirtualRouter(name="default",
                       interface=["ethernet1/1", "ethernet1/3", "ethernet1/4"],
                       )

#append children objects
router.children.append(def_static_r1)

fw.add(router)
router.create()

# creating basic security policies
from panos.policies import Rulebase, SecurityRule
allow_lan_to_wan = SecurityRule(name="allow_lan_to_wan",
                            fromzone="LAN",
                            tozone="WAN",
                            action="allow")

deny_wan_to_lan = SecurityRule(name="deny_wan_to_lan",
                            fromzone="WAN",
                            tozone="LAN",
                            action="deny")

allow_wan_to_dmz = SecurityRule(name="allow_wan_to_dmz",
                        fromzone="WAN",
                        tozone="DMZ",
                        action="allow")                       

allow_dmz_to_wan = SecurityRule(name="allow_dmz_to_wan",
                        fromzone="DMZ",
                        tozone="WAN",
                        action="allow")

allow_lan_to_dmz = SecurityRule(name="allow_lan_to_dmz",
                        fromzone="LAN",
                        tozone="DMZ",
                        action="allow")

deny_dmz_to_lan = SecurityRule(name="deny_dmz_to_lan",
                        fromzone="DMZ",
                        tozone="LAN",
                        action="deny")

#this rule was set while initial testing scenarios number 2
#deny_wan_to_dmz = SecurityRule(name="deny_wan_to_dmz",
#                        fromzone="WAN",
#                        tozone="DMZ",
#                        action="deny")

rb = Rulebase()
fw.add(rb)

for rule in [allow_lan_to_wan, allow_wan_to_dmz, allow_lan_to_dmz, deny_wan_to_lan, allow_dmz_to_wan, deny_dmz_to_lan]:
    rb.add(rule)
allow_lan_to_dmz.create_similar()

#It is crucial to remember that dhcp servers need to be configured manually to make sure hosts receivce IP addresses

