# IPFS Storage Engine

We are implementing the `Put()` and `Get()` API methods on top of IPFS.

`ipfs.go`: storage provider implementation

`cmd/main.go`: interacting with IPFS storage provider. This requires the IPFS daemon to be running.

## Installation

1. Install IPFS daemon:
    - Download `ipfs` binary
2. Initialize IPFS
    - Execute `ipfs init` (only needs to be done once)
    - Add the core wave3 peers to your network
3. Run IPFS daemon
    - Execute `ipfs daemon --enable-pubsub-experiment`
4. Install WAVE storage provider:
    - **TODO**

## Usage


### Supernode

Supernodes are servers that have voluntarily taken on the role of storing WAVE objects from IPFS clients.

1. Clone and follow instructions for ansible
    - [IPFS WAVE IPFS supernode setup](https://github.com/gtfierro/ansible-ipfs-cluster)


### Put/Get

We have a simple command line interface for now

1. `cmd put <file path>` returns hash
1. `cmd put <hash>` prints the contents of the file on the screen

### Adding Supernodes

Put the bootstrap peers in a file `bootstrappeers` and run

```bash
while read addr; do
    ipfs bootstrap add $addr
    ipfs swarm connect $addr
done < bootstrappeers
```

```
/ip4/54.183.252.14/tcp/4001/ipfs/QmWaDiSZhFn9JYjtUMp2wXP7j6yjaVrxdjSZKfGjaYzTjM
```
