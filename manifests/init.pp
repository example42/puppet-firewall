#
# This is left here solely for BC purposes
# Consider using firewall::rule instead.
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
  $enable         = $firewall::setup::enable,
  $enable_v6      = $firewall::setup::enable_v6
  ) {

  include firewall::setup

  if "iptables::rule::${tool}" != $firewall::setup::rule_class and $tool != '' {
    fail("The supplied firewall class differs with the one set in
          \$firewall::rule_class ('${firewall::setup::rule_class}').
          Make sure they match, and consider using firewall::rule directly.")
  }

  firewall::rule { $name:
    source         => $source,
    source_v6      => $source_v6,
    destination    => $destination,
    destination_v6 => $destination_v6,
    protocol       => $protocol,
    port           => $port,
    action         => $action,
    direction      => $direction,
    order          => $order,
    enable         => $enable,
    enable_v6      => $enable_v6
  }
}
