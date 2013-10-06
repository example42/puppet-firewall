
class firewall::setup (
  $in_interface     = '',
  $out_interface    = '',
  $order            = $firewall::params::order,
  $log              = $firewall::params::log,
  $log_prefix       = $firewall::params::log_prefix,
  $log_limit_burst  = $firewall::params::log_limit_burst,
  $log_limit        = $firewall::params::log_limit,
  $log_level        = $firewall::params::log_level,
  $source           = '',
  $source_v6        = '',
  $destination      = '',
  $destination_v6   = '',
  $protocol         = '',
  $port             = '',
  $action           = '',
  $direction        = '',
  $enable           = true,
  $enable_v4        = $firewall::params::enable_v4,
  $enable_v6        = $firewall::params::enable_v6,
  $debug            = false,

  # Iptables specifics
  $iptables_table   = 'filter',
  $iptables_chains  = $firewall::params::iptables_chains,
  $iptables_targets = $firewall::params::iptables_targets,
) inherits firewall::params {

  $rule_class = $firewall::params::rule_class

}
