# Puppet module: firewall

This is a Puppet abstraction module to manage firewalling.

Made by Alessandro Franceschi / Lab42 - http://www.example42.com

Released under the terms of Apache 2 License.

Check Modulefile for dependencies.

## Goal of this module
This module abstracts the firewalling definitions for an host or application, in order to add and use different firewalling methods, without changes on the single application modules. It provides:
- a common interface for different firewalling tools (currently only local host based iptables)
- an unified syntax for firewalling resources able to adapt to firewalling modules from different authors
- a standard way to define what an application or an host needs to be firewalled
- reversable actions (you can remove a firewall resource previously defined)

## Usage
In order to activate automatic firewalling for the port(s) opened by the service(s) provided by a module you have to pass, at least, these parameters:

        class { "foo":
          firewall      => true,
          firewall_tool => "iptables",
          firewall_src  => "10.42.0.0/24",
          firewall_dst  => "$ipaddress_eth0",
        }

where firewall_tool is a string or an array of the firewalling tools you want to activate (curretly is supposed only local iptables firewalling with Example42's iptables module). $firewall_src is the source ip address / netmask (may be 0.0.0.0/0) to allow access, and $firewall_dst is the destination address (may be a facter variable.

### IPv6
In order to enable IPv6 there have to be configured two parts:
- iptables should be IPv6 enabled:
          class{ 'iptables' :
            enable_v6 => true,
          }
- then firewall rules can be IPv6 enabled also:
        firewall { 'http': 
          port       => '80',
          protocol   => 'tcp',
          enable_v6  => true,
        }
        
If specific source / destination adresses should be used, a definition will look like: 
        firewall { 'http':
          source          => '10.42.0.0/24',
          source_v6       => '2001:0db8:3c4d:0015:0000:0000:abcd:ef12',
          destination     => '$ipaddress_eth0',
          destination_v6  => '2001:470:27:37e::2/64', 
          port            => '80',
          protocol        => 'tcp',
          enable_v6       => true,
        }
        
## Dependencies

This is a meta-module that needs dependencies according to the firewall tools modules you use (currently only Example42's iptablles module is supported).
It requires Example42's Puppi and Iptables modules.

## Status of the module
This module is derived from the firewall module of the first generation of Example42 Puppet modules.

Work and adaptation for the second generation of Example42 Puppet module is in progress, some features may be added or modified.

## Testing

[![Build Status](https://travis-ci.org/example42/puppet-firewall.png?branch=master)](https://travis-ci.org/example42/puppet-firewall)

