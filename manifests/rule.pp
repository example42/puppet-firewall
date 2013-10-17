
# A generic firewall define to abstract firewalling rules from the actual
# firewalling tool to use.
# Currently only the "iptables" tool is supported, which makes use of
# Example42's iptables module for host based local firewalling
#
# [*source*]
#   The packets source address (in iptables --source
#   supported syntax). Can be an array of sources.
#
# [*source_v6*]
#    The packets IPv6 source address. Can be an array of sources.
#
# [*destination*]
#    The packets destination (in iptables --destination
#    supported syntax). Can be an array of destinations.
#
# [*destination_v6*]
#   The packets IPv6 destination. Can be an array of destinations.
#
# [*protocol*]
#   The transport protocol (tcp,udp,icmp, anything from /etc/protocols )
#
# [*port*]
#   The DESTINATION port
#
# [*action*]
#   Either 'drop', 'deny' or 'accept'
#
# [*direction*]
#   Either 'input', 'output', 'forward'
#
# [*order*]
#   The CONCAT order where to place your rule.
#
# [*in_interface*]
#   The inbound interface for the rule
#
# [*out_interface*]
#   The outbound interface for the rule
#
# [*log*]
#    Bool. To log the traffic matched by this rule. Default false
#
# [*log_prefix*]
#   Prefix for the lines logged
#
# [*log_limit*]
#   Limit the logging based on iptables --limit directive
#
# [*log_level*]
#   The Iptables log level directive
#
# [*enable*]
#   To enable, or not to enable. That's the question.
#
# [*enable_v4*]
#   Enable IPv4. Defaults to true
#
# [*enable_v6*]
#   Enable IPv6. Defaults to true.
#
# [*debug*]
#   Enable debugging.
#
# [*resolve_locations*]
#   Resolve any hostnames that are in $source, $source_v6,
#   $destination and $destination_v6. This means that:
#   V4: [ '127.0.0.1', 'www.example42.com' ]
#   Becomes: [ '127.0.0.1', '176.9.65.210' ]
#
#   V6: [ '::1', 'www.example42.com' ]
#   Becomes: [ '::1' ] (example42.com doesn't resolve any AAAA records yet
#
# [*resolve_failsafe*]
#   Bool. Default true. Disable the given IP version if no hosts could be
#   resolved. Looks at source ip if $real_direction == input, destination ip if
#   $real_direction == output. Does nothing with forward traffic (yet).
#
# [*iptables_chain*]
#   The iptables chain to work on (default INPUT).
#   Write it UPPERCASE coherently with iptables syntax
#
# [*iptables_implicit_matches*]
#   An hashmap with implicit match criteria with the possibility to negate
#   specific matches:
#   { 'dport' => 80, 'tcp-flags' => 'ACK', 'invert' => [ 'tcp-flags'] }
#   Results in: --dport 80 --tcp-flags ! ACK
#
#   See here for a full list of possible implicit criteria:
#     http://www.iptables.info/en/iptables-matches.html#IMPLICITMATCHES
#
# [*iptables_explicit_matches*]
#   An hashmap with explicit match criteria with the possibility to negate
#   specific matches:
#   { 'icmp' => { 'icmp-type' => 8 }, 'hashlimit' => { 'hashlimit' => '1000/sec } }
#   Results in: -m icmp --icmp-type 8 -m hashlimit --hashlimit 1000/sec
#
# [*iptables_target_options*]
#   A hashmap with key=>values of options to be appended after the target.

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
  $enable_v4        = $firewall::setup::enable_v4,
  $enable_v6        = $firewall::setup::enable_v6,
  $debug            = false,
  $resolve_locations = true,
  $resolve_failsafe = true,

  # Iptables specifics
  $iptables_chain            = '',
  $iptables_implicit_matches = {},
  $iptables_explicit_matches = {},
  $iptables_target_options   = {},
  $iptables_rule             = '',
) {

  include firewall::setup

  $real_direction = $direction ? {
    ''      => 'input',
    default => inline_template('<%= @direction.downcase %>')
  }

  if any2bool($enable_v4) and any2bool($resolve_locations) {
    $real_source = firewall_resolve_locations($source, '4')
    $real_destination = firewall_resolve_locations($destination, '4')
    $real_enable_v4 = any2bool($resolve_failsafe) ? {
      false => $enable_v4,
      default => 
         (
           (!('0' != inline_template('<%=@source.length %>') and 
           '0' == inline_template('<%=@real_source.length %>')) and
           $real_direction == 'input')
          ) or (
           (!('0' != inline_template('<%=@destination.length %>') and 
           '0' == inline_template('<%=@real_destination.length %>')) and
           $real_direction == 'output')
          ) or ($real_direction != 'input' and $real_direction != 'output' ) # This line needs changing. Some time
    }
  } else {
    $real_source      = $source
    $real_destination = $destination
    $real_enable_v4   = $enable_v4
  }

  if any2bool($enable_v6) and any2bool($resolve_locations) {
    $real_source_v6 = firewall_resolve_locations($source_v6, '6')
    $real_destination_v6 = firewall_resolve_locations($destination_v6, '6')
    $real_enable_v6 = any2bool($resolve_failsafe) ? {
      false => $enable_v6,
      default => 
         (
           (!('0' != inline_template('<%=@source_v6.length %>') and 
           '0' == inline_template('<%=@real_source_v6.length %>')) and
           $real_direction == 'input')
          ) or (
           (!('0' != inline_template('<%=@destination_v6.length %>') and 
           '0' == inline_template('<%=@real_destination_v6.length %>')) and
           $real_direction == 'output')
          ) or ($real_direction != 'input' and $real_direction != 'output' ) # This line needs changing. Some time
    }
    
  } else {
    $real_source_v6      = $source_v6
    $real_destination_v6 = $destination_v6
    $real_enable_v6      = $enable_v6
  }

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

    $chain = $iptables_chain ? {
      ''      => $firewall::setup::iptables_chains[$real_direction],
      default => $iptables_chain
    }
    include iptables
    iptables::rule { $name:
      chain            => $chain,
      target           => $firewall::setup::iptables_targets[$action],
      in_interface     => $in_interface,
      out_interface    => $out_interface,
      source           => $real_source,
      source_v6        => $real_source_v6,
      destination      => $real_destination,
      destination_v6   => $real_destination_v6,
      protocol         => $protocol,
      port             => $port,
      order            => $real_order,
      log              => $log,
      log_prefix       => $log_prefix,
      log_limit_burst  => $log_limit_burst,
      log_limit        => $log_limit,
      log_level        => $log_level,
      enable           => $enable,
      enable_v4        => $real_enable_v4,
      enable_v6        => $real_enable_v6,
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

    fail('No firewall class was matched')
  }

}
