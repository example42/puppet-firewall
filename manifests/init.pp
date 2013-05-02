# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#
define firewall (
  $source         = undef,
  $source_v6      = undef,
  $destination    = undef,
  $destination_v6 = undef,
  $protocol       = undef,
  $port           = '',
  $action         = '',
  $direction      = '',
  $order          = '',
  $tool           = '',
  $enable         = true,
  $enable_v6      = false
  ) {
  # Define standard firewall tool
  $stdfw_tool = $::osfamily ? {
  	/(?i:Solaris)/                                           => 'ipfilter',
  	/(?i:Debian|Ubuntu|Mint|SLES|Gentoo|Mandrake|Archlinux)/ => 'iptables',
  	default                                                  => '',
  }
  # Choose tool to use
  $real_tool = $tool ? {
  	''      => $stdfw_tool,
  	default => $tool,
  }

  case $real_tool {
    'iptables': {
      $iptables_chain = $direction ? {
        'output'  => 'OUTPUT',
        'forward' => 'FORWARD',
        default   => 'INPUT',
      }

      $iptables_target = $action ? {
        'deny'    => 'DROP',
        'drop'    => 'DROP',
        'reject'  => $protocol ? {
          'tcp'   => 'REJECT --reject-with tcp-reset',
          default => 'REJECT',
        },
        default   => 'ACCEPT',
      }

      iptables::rule { $name:
        chain           => $iptables_chain,
        target          => $iptables_target,
        source          => $source,
        source_v6       => $source_v6,
        destination     => $destination,
        destination_v6  => $destination_v6,
        protocol        => $protocol,
        port            => $port,
        order           => $order,
        enable          => $enable,
        enable_v6       => $enable_v6,
      }
    }
    'ipfilter': {
      $ipfilter_dir = $direction ? {
        'output'  => 'out',
        default   => 'in',
      }
      $ipfilter_action = $action ? {
        'deny'    => 'block',
        'drop'    => 'block',
        'reject'  => 'block return-icmp-as-dest(3)',
        default   => 'pass',
      }
      ipfilter::rule { $name:
        direction       => $ipfilter_dir,
        action          => $ipfilter_action,
        source          => $source,
        source_v6       => $source_v6,
        destination     => $destination,
        destination_v6  => $destination_v6,
        protocol        => $protocol,
        port            => $port,
        order           => $order,
        enable          => $enable,
        enable_v6       => $enable_v6,
      }
    }
    default: {
      fail("FIREWALL: Tool = ${tool} is not supported.")
    }
  }
}
