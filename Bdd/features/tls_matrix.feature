@tls @tls_matrix
Feature: TLS equivalence matrix
  Given equivalent configuration, SolidSyslog reaches the same decision on
  every target - the same connect-or-refuse outcome, and the same portable
  detail code from enum SolidSyslogTlsStreamErrors. Each cell runs on every
  BDD lane, so one that passes has been proved against both TLS libraries,
  both collectors and every transport the library ships.

  The library that spoke is never asserted. It is the one thing that is
  supposed to differ.

  Scenario: A peer signed by the trusted anchor and named as expected is authorised
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the syslog oracle receives a message with priority "134"
    And the target reports no TLS fault

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

  Scenario: A device that authenticates itself as well delivers over mutual TLS
    Given the syslog oracle is running
    When the BDD target sends a syslog message with transport mtls
    Then the syslog oracle receives 1 message over mtls
    And the syslog oracle receives a message with priority "134"
    And the target reports no TLS fault

  Scenario: A device that declares no peer name delivers, and says the peer is unnamed
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target declares no expected peer name
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports TLS detail "SERVER_NAME_NOT_SET" at severity WARNING

  Scenario: A client credential the library cannot complete does not stop delivery
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target holds half a client credential
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls

  Scenario: A pin RFC 5425 makes mandatory but no longer trusts is honoured, and objected to
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the sha-1 fingerprint of "anchor-signed" is pinned
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports TLS detail "FINGERPRINT_SHA1" at severity WARNING

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

  Scenario: A cipher policy naming a suite the collector offers connects at the version it offers
    Given the syslog oracle is running
    And the collector presents "tls-1-2"
    And the BDD target asks for a suite the collector offers
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  @tls13
  Scenario: A device connects at TLS 1.3 to a collector that refuses anything older
    # Both oracles refuse everything below 1.3 on this listener - syslog-ng
    # through ssl-options, otelcol through min_version - so delivery is what
    # proves the version negotiated. The library has no 1.3 knob; it happens
    # because each backend prefers the highest mutually supported version.
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    When the BDD target sends a syslog message with transport tls
    Then the syslog oracle receives 1 message over tls
    And the target reports no TLS fault

  Scenario: A cipher policy the collector cannot satisfy is refused rather than quietly widened
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target asks for a suite the collector does not offer
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "HANDSHAKE_REJECTED"
    And the syslog oracle receives no message over tls
    And the BDD target is still running

  Scenario: Rotating the trust anchors lets a refused device deliver without a restart
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target trusts certificate authority "ca-b"
    And the BDD target tolerates a refused handshake
    When the BDD target attempts to send a syslog message over tls
    Then the target reports TLS detail "PEER_CERTIFICATE_UNTRUSTED"
    And the syslog oracle receives no message over tls
    When the client is given trust anchors "ca"
    And the client sends a message
    Then the syslog oracle receives 1 message over tls

  Scenario: Rotating the pin set stops a delivering device at its next connection
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the fingerprint of "anchor-signed" is pinned
    And the BDD target tolerates a refused handshake
    And the BDD target is running with default transport tls
    When the client sends a message
    Then the syslog oracle receives 1 message over tls
    When the client is given the pin of "collector-b"
    And the client sends a message
    Then the target reports TLS detail "PEER_FINGERPRINT_MISMATCHED"
    And the syslog oracle receives 1 message over tls

  Scenario: Rotating the expected peer name stops a delivering device
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target tolerates a refused handshake
    And the BDD target is running with default transport tls
    When the client sends a message
    Then the syslog oracle receives 1 message over tls
    When the client expects the peer name "not-the-collector"
    And the client sends a message
    Then the target reports TLS detail "PEER_NAME_MISMATCHED"
    And the syslog oracle receives 1 message over tls

  Scenario: A redirected device carries the identity it expects with it
    Given the syslog oracle is running
    And the collector presents "anchor-signed"
    And the BDD target tolerates a refused handshake
    And the BDD target is running with default transport tls
    When the client sends a message
    Then the syslog oracle receives 1 message over tls
    When the client is redirected to "collector-b"
    And the client is given trust anchors "ca-b"
    And the client expects the peer name "collector-b"
    And the client sends a message
    Then the syslog oracle receives 1 message over tls_b
    And the target reports no TLS fault

  Scenario: Rotating in the client credential lets a refused device deliver
    Given the syslog oracle is running
    And the collector presents "mtls-required"
    And the BDD target tolerates a refused handshake
    And the BDD target is running with default transport tls
    When the client sends a message
    Then the syslog oracle receives no message over mtls
    When the client is given the client credential "client"
    And the client sends a message
    Then the syslog oracle receives 1 message over mtls
