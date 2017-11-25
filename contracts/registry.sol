pragma solidity ^0.4.0;

contract Registry {

  //Entities
  struct Entity {
    address controller;
    bytes data;
  }

  struct DotPointer {
    bytes32 hash;
    /* 1 = in this contract
       2 = in swarm
     */
    uint location;
  }

  // SLOT 0 Hash -> primary content
  mapping(bytes32 => Entity) public entities;

  // Slot 1 DST Hash -> dot pointer
  mapping(bytes32 => DotPointer[]) public dots;

  // Slot 2 Dot Hash -> content (on chain)
  mapping(bytes32 => bytes) public dotsByHash;

  // Slot 3 Revocation hash -> revocation
  mapping(bytes32 => bytes) public revocations;

  event EntityRegistered(bytes32 indexed hash);
  event DOTRegistered(bytes32 indexed hash, bytes32 indexed dst, uint indexed location);
  event RevocationRegistered(bytes32 indexed hash);

  function registerEntity(bytes data) public {
    //Entity must not already exist
    require(data.length > 96);
    bytes32 hsh = keccak256(data);
    require(entities[hsh].controller == 0);

    //Set the controller
    entities[hsh].controller = msg.sender;
    //Set the data
    entities[hsh].data = data;
    EntityRegistered(hsh);
  }

  function registerDot(bytes32 dsthash, bytes data) public {
    require(data.length > 256);
    bytes32 hsh = keccak256(data);
    dotsByHash[hsh] = data;
    DotPointer memory p;
    p.hash = hsh;
    p.location = 1;
    dots[dsthash].push(p);
    DOTRegistered(hsh, dsthash, 1);
  }

  function registerOffChainDot(bytes32 dsthash, bytes32 hash, uint location) public {
    DotPointer memory p;
    p.hash = hash;
    p.location = location;
    dots[dsthash].push(p);
    DOTRegistered(hash, dsthash, location);
  }

  function registerRevocation(bytes data) public {
    bytes32 hsh = keccak256(data);
    revocations[hsh] = data;
    RevocationRegistered(hsh);
  }
}
