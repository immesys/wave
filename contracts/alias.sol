pragma solidity ^0.4.0;

/*
Aliases are now

subdomain.domain.tld

a TLD is controlled by an entity
domain.tld implicitly gets converted to subdomain.domain.tld where subdomain
is the latest created subdomain
*/

contract AliasRegistry {

  struct Domain {
    bytes32 head;
    mapping(bytes32 => bytes) subdomains;
  }

  struct TLD {
    address controller;
    mapping(bytes32 => Domain) domains;
  }

  // SLOT 0 TLD -> controlling account
  mapping(bytes32 => TLD) public toplevels;

  function CreateTLD(bytes32 tld) public {
    //Entity must not already exist
    require(toplevels[tld].controller == 0);
    //Set the controller
    toplevels[tld].controller = msg.sender;
  }

  function CreateSubdomain(bytes32 tld, bytes32 domain, bytes32 subdomain, bytes value) public {
    require(toplevels[tld].controller == msg.sender);
    toplevels[tld].domains[domain].subdomains[subdomain] = value;
    toplevels[tld].domains[domain].head = subdomain;
  }

  function GetHead(bytes32 tld, bytes32 domain) constant public returns (bytes32 head) {
    return toplevels[tld].domains[domain].head;
  }

  function GetSubdomain(bytes32 tld, bytes32 domain, bytes32 subdomain) constant public returns (bytes v) {
    return toplevels[tld].domains[domain].subdomains[subdomain]
  }

}
