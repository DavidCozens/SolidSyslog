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
