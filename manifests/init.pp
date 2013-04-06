# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#
define firewall (
  $source         = '',
  $source_v6      = '',
  $destination    = '',
  $destination_v6 = '',
  $protocol       = '',
  $port           = '',
  $action         = '',
  $direction      = '',
  $order          = '',
  $tool           = 'iptables',
  $enable         = true,
  $enable_v6      = false
  ) {

  if ($tool =~ /iptables/) {

    # FIXME: Unsure if this should be in firewall or iptables. Maybe both?
    # iptables-restore v1.3.5: Unknown arg `--dport'
    # -A INPUT  --dport 21   -j REJECT
    if ($protocol == '') and ($port) {
      fail('FIREWALL: Protocol must be set if port is set.')
    }

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
}
