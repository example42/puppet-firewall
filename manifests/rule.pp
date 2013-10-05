
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

  if ($firewall::setup::rule_class =~ /iptables/) {

    # TODO: Would rather use this statement, but can't. Blaming a Puppet Bug (TBD)
    # The get_class_args() call adds a dependency on puppi
    # create_resources("iptables::rule::iptables", get_class_args())
  
    firewall::rule::iptables { $name:
      source           => $source,
      source_v6        => $source_v6,
      destination      => $destination,
      destination_v6   => $destination_v6,
      protocol         => $protocol,
      port             => $port,
      action           => $action,
      direction        => $direction,
      order            => $order,
      in_interface     => $in_interface,
      out_interface    => $out_interface,
      log              => $log,
      log_prefix       => $log_prefix,
      log_limit_burst  => $log_limit_burst,
      log_limit        => $log_limit,
      log_level        => $log_level,
      enable           => $enable,
      enable_v4        => $enable_v4,
      enable_v6        => $enable_v6,
      debug            => $debug,

      iptables_chain            => $iptables_chain,
      iptables_implicit_matches => $iptables_implicit_matches,
      iptables_explicit_matches => $iptables_explicit_matches,
      iptables_target_options   => $iptables_target_options,
      iptables_rule             => $iptables_rule,
    }
  }

}
