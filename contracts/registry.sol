pragma solidity ^0.4.0;

contract Registry {

  //Entities
  struct Entity {
    address controller;
    bytes data;
    bool revokable;
  }

  struct DotPointer {
    bytes32 hash;
    /* 1 = in this contract
       2 = in swarm
     */
    uint storageType;
  }

  // SLOT 0 VK -> primary content
  mapping(bytes32 => Entity) public entities;

  // SLOT 1 VK -> field changes
  mapping(bytes32 => bytes[]) fieldChange;

  // SLOT 2 VK -> attestations
  mapping(bytes32 => bytes[]) fieldAttestations;

  // SLOT 3 VK -> revocation status
  mapping(bytes32 => bool) entityRevoked;

  // Slot 4 DST VK -> dot pointer
  mapping(bytes32 => DotPointer[]) public dots;

  // Slot 5 Dot Hash -> content (on chain)
  mapping(bytes32 => bytes) public dotsByHash;

  //TODO entity expiry
  function registerEntity(bytes32 vk, bool revokable, bytes data) public {
    //Entity must not already exist
    require(entities[vk].controller == 0);
    require(data.length > 96);
    //Set the controller
    entities[vk].controller = msg.sender;
    entities[vk].data = data;
    entities[vk].revokable = revokable;
  }

  function registerFieldChange(bytes32 vk, bytes data) public {
    require(msg.sender == entities[vk].controller);
    require(data.length > 64);
    fieldChange[vk].push(data);
  }

  function registerRevocation(bytes32 vk) public {
    require(msg.sender == entities[vk].controller);
    require(entities[vk].revokable);
    entityRevoked[vk] = true;
  }

  //Attestation must be "accepted" by the VK by publishing it
  function registerAttestation(bytes32 vk, bytes data) public {
    require(msg.sender == entities[vk].controller);
    require(data.length > 96);
    fieldAttestations[vk].push(data);
  }

  function registerDot(bytes32 dstvk, bytes data) public {
    require(data.length > 256);
    var hsh = keccak256(data);
    dotsByHash[hsh] = data;
    DotPointer memory p;
    p.hash = hsh;
    p.storageType = 1;
    dots[dstvk].push(p);
  }

  function registerOffChainDot(bytes32 dstvk, bytes32 hash, uint storageType) public {
    DotPointer memory p;
    p.hash = hsh;
    p.storageType = storageType;
    dots[dstvk].push(p);
  }

// "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

//1515856
}
