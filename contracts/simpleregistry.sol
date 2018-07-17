pragma solidity ^0.4.0;

contract Registry {
  mapping(bytes32 => bytes) public objects;
  mapping(bytes32 => bytes32[]) public queues;

  function put(bytes data) public {
    objects[keccak256(data)] = data;
  }

  function enqueue(bytes32 queue, bytes32 hash) public {
    queues[queue].push(hash);
  }
}
