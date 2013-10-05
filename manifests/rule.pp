
# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#

define firewall::rule (
  $source           = '',
  $source_v6        = '',
  $destination      = '',
  $destination_v6   = '',
  $protocol         = '',
  $port             = '',
  $action           = '',
  $direction        = '',
  $order            = '',
  $in_interface     = '',
  $out_interface    = '',
  $log              = $firewall::setup::log,
  $log_prefix       = $firewall::setup::log_prefix,
  $log_limit_burst  = $firewall::setup::log_limit_burst,
  $log_limit        = $firewall::setup::log_limit,
  $log_level        = $firewall::setup::log_level,
  $enable           = true,
  $enable_v4        = $iptables::bool_enable_v4,
  $enable_v6        = $iptables::bool_enable_v6,
  $debug            = false,

  # Iptables specifics
  $iptables_chain            = '',
  $iptables_implicit_matches = {},
  $iptables_explicit_matches = {},
  $iptables_target_options   = {},
  $iptables_rule             = '',
) {
  
  include firewall::setup

  if ($firewall::setup::rule_class =~ /firewall::rule::iptables/) {

    # Embedded here for performance reasons
  
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
  } else {
    # TODO: Would rather use this statement, but can't. Blaming a Puppet Bug (TBD)
    # The get_class_args() call adds a dependency on puppi
    # create_resources($firewall::setup::rule_class, get_class_args())
    
#    fail('No firewall class was matched')
  }

}
