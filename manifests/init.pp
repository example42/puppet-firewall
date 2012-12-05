# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#
define firewall (
  $source      = '',
  $destination = '',
  $protocol    = '',
  $port        = '',
  $action      = '',
  $direction   = '',
  $tool        = 'iptables',
  $enable      = true
  ) {

  if ($tool =~ /iptables/) {

    $iptables_chain = $direction ? {
      'output'  => 'OUTPUT',
      'forward' => 'FORWARD',
      default   => 'INPUT',
    }

    $iptables_target = $action ? {
      'deny'    => 'DROP',
      'drop'    => 'DROP',

      'reject'  => $protocol ? {
        'tcp'   => "REJECT --reject-with tcp-reset",
        default => "REJECT", 
      },

      default   => 'ACCEPT',
    }

    iptables::rule { $name:
      chain       => $iptables_chain,
      target      => $iptables_target,
      source      => $source,
      destination => $destination,
      protocol    => $protocol,
      port        => $port,
      enable      => $enable,
    }

  }

}
