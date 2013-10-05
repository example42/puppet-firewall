define firewall::rule::iptables (
  $source,
  $source_v6,
  $destination,
  $destination_v6, 
  $protocol,     
  $port,
  $action,
  $direction,
  $order,
  $in_interface,
  $out_interface,
  $log,
  $log_prefix,
  $log_limit_burst,
  $log_limit,
  $log_level,
  $enable,
  $enable_v4,
  $enable_v6,
  $debug,

  # Iptables specifics
  $iptables_chain,
  $iptables_implicit_matches,
  $iptables_explicit_matches,
  $iptables_target_options,
  $iptables_rule,
) {

    # FIXME: Unsure if this should be in firewall or iptables. Maybe both?
    # TODO: Move to iptables - beware of implicit-matches though
    # iptables-restore v1.3.5: Unknown arg `--dport'
    # -A INPUT  --dport 21   -j REJECT
    if ($protocol == '') and ($port) {
      fail('FIREWALL: Protocol must be set if port is set.')
    }

    $real_order = $order ? {
      ''      => $firewall::setup::order,
      default => $order
    }

    iptables::rule { $name:
      chain            => $firewall::setup::iptables_chains[$iptables_chain],
      target           => $firewall::setup::iptables_targets[$action],
      in_interface     => $in_interface,
      out_interface    => $out_interface,
      source           => $source,
      source_v6        => $source_v6,
      destination      => $destination,
      destination_v6   => $destination_v6,
      protocol         => $protocol,
      port             => $port,
      order            => $real_order,
      log              => $log,
      log_prefix       => $iptables::log_prefix,
      log_limit_burst  => $iptables::log_limit_burst,
      log_limit        => $iptables::log_limit,
      log_level        => $iptables::log_level,
      enable           => $enable,
      enable_v4        => $iptables::bool_enable_v4,
      enable_v6        => $iptables::bool_enable_v6,
      debug            => $debug,
      implicit_matches => $iptables_implicit_matches,
      explicit_matches => $iptables_explicit_matches,
      target_options   => $iptables_target_options,
      rule             => $iptables_rule
    }
}
