@tls @tls_matrix
Feature: TLS equivalence matrix
  Given equivalent configuration, SolidSyslog reaches the same decision on
  every target - the same connect-or-refuse outcome, and the same portable
  detail code from enum SolidSyslogTlsStreamErrors. Each cell runs on every
  BDD lane, so one that passes has been proved against both TLS libraries,
  both collectors and every transport the library ships.

  The library that spoke is never asserted. It is the one thing that is
  supposed to differ.

  Scenario: A pinned certificate is authorised with no chain at all
    Given the syslog oracle is running
    And the collector presents "self-signed"
    And the BDD target trusts no certificate authority
    And the fingerprint of "self-signed" is pinned
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  Scenario: A peer presented with its issuer satisfies both the anchor and the pin
    Given the syslog oracle is running
    And the collector presents "chained"
    And the fingerprint of "chained" is pinned
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  Scenario: A pin set holding a certificate the collector no longer presents keeps delivering
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the fingerprint of "collector-b" is pinned
    And the fingerprint of "anchor-signed" is pinned
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  Scenario: Opting out of the peer name check accepts a name that would not have matched
    Given the syslog oracle is running
    And the collector presents "wrong-name"
    And the BDD target opts out of the peer name check
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  Scenario: A peer that does not chain to the trusted anchor is refused
    Given the syslog oracle is running
    And the collector presents "untrusted"
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "PEER_CERTIFICATE_UNTRUSTED"
    And the syslog oracle receives no message over tls
    And the BDD target is still running

  Scenario: A peer whose certificate names another host is refused
    Given the syslog oracle is running
    And the collector presents "wrong-name"
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "PEER_NAME_MISMATCHED"
    And the syslog oracle receives no message over tls
    And the BDD target is still running

  Scenario: A pin matching nothing the collector presents is refused
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the fingerprint of "collector-b" is pinned
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "PEER_FINGERPRINT_MISMATCHED"
    And the syslog oracle receives no message over tls
    And the BDD target is still running

  Scenario: A device given neither anchors nor pins never connects, and says why
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target trusts no certificate authority
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "NO_PEER_AUTHORISATION"
    And the syslog oracle receives no message over tls
    And the BDD target is still running
