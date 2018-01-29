package partindex

const NSLOT
const SZ
// The problem is how to turn the following calls:
// putkey (key [][]byte, val []byte)
// putciphertext (key [][]byte, val []byte)
// getmatchingkeys (ciphertext [][]byte) []byte
// getmatchingciphertexts (key [][]byte) []byte
// into llstorage compatible keys.
// the rules of the key are:
// the dimensions are [NSLOT][SZ]byte but the inner byte slice can be nil
// the matching is match(key, ciphertext) = true IFF for every slot, key[i] == nil || key[i] == ciphertext[i]
// and we need to be able to efficiently look up both ways

/*

Options 1: serialize as string, when matching, selectively replace slots with nil and do equality
        > bad, with NSLOT 20 there are too many permutations

Option 2: store NSLOT copies of each entry and traverse the ranges in parallel, merging
        > bad, the selectivity of a single slot is low

Option 3: build up a list of prefixes, and breadth first search as you would through a graph




*/
