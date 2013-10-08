class firewall::params (
  $rule_class = 'firewall::rule::iptables'
) {

  if $rule_class =~ /firewall::rule::iptables/ {

    include iptables

    $order = $iptables::default_order

    $iptables_chains = {
      'output'  => 'OUTPUT',
      'forward' => 'FORWARD',
      'input'   => 'INPUT',
      ''        => 'INPUT'
    }

    $iptables_targets = {
      'deny'    => 'DROP',
      'drop'    => 'DROP',
      'reject'  => 'REJECT',
      'accept'  => 'ACCEPT',
      ''        => $iptables::default_target
    }

    $log             = $iptables::log == 'all'
    $log_prefix      = $iptables::log_prefix
    $log_limit_burst = $iptables::log_limit_burst
    $log_limit       = $iptables::log_limit
    $log_level       = $iptables::log_level

    $enable_v4       = $iptables::bool_enable_v4
    $enable_v6       = $iptables::bool_enable_v6
    $target          = $iptables::default_target

  }
}
