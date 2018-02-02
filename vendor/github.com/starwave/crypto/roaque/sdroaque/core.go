package sdroaque

import (
	"io"
	"math"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

type Params struct {
	userSize *int
	attrSize *int
	height   *int
	params   *oaque.Params
}

//	This should be out of band, and managed by namespace
//	userNumber *int

type MasterKey struct {
	masterKey *oaque.MasterKey
}

// Key[i] for sets S_{left[i],right[i]}.
type privateKeyNode struct {
	left, right []int
	privateKey  []*oaque.PrivateKey
}

//	PrivateKey is a set of keys. Each setKey[i] contain keys of all the sets which
//  cover leaf node i.
type PrivateKey struct {
	lEnd, rEnd *int
	// Index starts from 0
	attrs  oaque.AttributeList
	setKey []*privateKeyNode
}

type RevocationList []int

type Ciphertext struct {
	cipher      *oaque.Ciphertext
	left, right *int
}

type CiphertextList []*Ciphertext

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 1 to l-1). The parameter	"n" is the total number of users
// supported(indexed from 1 to n).
func Setup(random io.Reader, l int, n int) (*Params, *MasterKey, error) {
	params := &Params{}
	masterKey := &MasterKey{}
	var err error

	params.userSize, params.attrSize, params.height = new(int), new(int), new(int)
	*params.height = int(math.Ceil(math.Log2(float64(n))))
	*params.userSize = int(math.Floor(math.Exp2(float64(*params.height))))
	*params.attrSize = l

	// The first attribute represents i in S_{ij}. The latter ceil(log2(n) represents
	// j in S_{ij}.
	params.params, masterKey.masterKey, err = oaque.Setup(random, (1+*params.height)+l)
	if err != nil {
		return nil, nil, err
	}

	return params, masterKey, nil
}

func leafIndex(userSize int, index int) int {
	return index + userSize - 1
}

func getIndex(index int, maxSize int) []int {
	indexList := make([]int, 0, maxSize+1)
	for i := maxSize; i >= 0; i-- {
		if (index >> (uint(i))) != 0 {
			indexList = append(indexList, (index>>(uint(i)))&1)
		}
	}
	return indexList
}

// Return a new AttributeList contains original attrs and position of node vi and vk in
// the tree. vi is represented as the first attribute and vk is represented as the latter
// height attributes.
func newAttributeList(params *Params, vi int, vk int, attrs oaque.AttributeList) oaque.AttributeList {

	// NOTE: Assume attributeIndex is int
	newAttr := make(oaque.AttributeList)
	for index := range attrs {
		newAttr[oaque.AttributeIndex(*params.height+int(index))] = attrs[index]
	}

	//TODO: Add hash function here or inside oaque
	newAttr[oaque.AttributeIndex(0)] = big.NewInt(int64(vi))

	vkList := getIndex(vk, *params.height)
	for i := 1; i < len(vkList); i++ {
		newAttr[oaque.AttributeIndex(i)] = big.NewInt(int64(vkList[i]))
	}
	return newAttr
}

// Generate keys for a single leaf index.
func treeKeyGen(params *Params, master *MasterKey, attrs oaque.AttributeList, index int) (*privateKeyNode, error) {
	key := &privateKeyNode{}
	size := ((1 + *params.height) * *params.height) / 2
	key.left = make([]int, 0, size)
	key.right = make([]int, 0, size)
	key.privateKey = make([]*oaque.PrivateKey, 0, size)

	for i := (index >> 1); i != 0; i >>= 1 {
		for j := index; j != i; j >>= 1 {
			var k int
			if (j & 1) == 1 {
				k = j - 1
			} else {
				k = j + 1
			}

			attrsTmp := newAttributeList(params, i, k, attrs)
			var err error
			privateKey := &oaque.PrivateKey{}

			privateKey, err = oaque.KeyGen(nil, params.params, master.masterKey, attrsTmp)

			if err != nil {
				return nil, err
			}

			key.privateKey = append(key.privateKey, privateKey)
			key.left = append(key.left, i)
			key.right = append(key.right, k)
		}
	}

	return key, nil
}

// KeyGen generates a key for an attribute list using the master key.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. userNum is the number of current users in the system,
// and newUser is number of privateKey which namespace wants to generate.

func KeyGen(params *Params, master *MasterKey, attrs oaque.AttributeList, userNum int, newUser int) (*PrivateKey, error) {
	if newUser <= 0 || userNum < 0 || userNum+newUser > *params.userSize {
		panic("Parameters for KeyGen are out of bound")
	}

	key := &PrivateKey{}
	lEnd, rEnd := userNum+1, userNum+newUser
	var err error

	key.setKey = make([]*privateKeyNode, newUser, newUser)
	for i := lEnd; i <= rEnd; i++ {
		id := i - lEnd
		key.setKey[id], err = treeKeyGen(params, master, attrs, leafIndex(*params.userSize, i))
		if err != nil {
			return nil, err
		}
	}

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd, *key.rEnd = lEnd, rEnd
	key.attrs = make(oaque.AttributeList)
	for index := range attrs {
		key.attrs[index] = attrs[index]
	}
	return key, nil
}

// Qualify key for a leaf node
func qualifyKeyNode(params *Params, qualify *privateKeyNode, attrs oaque.AttributeList) (*privateKeyNode, error) {
	setKey := &privateKeyNode{}
	var err error

	size := len(qualify.left)
	setKey.left = make([]int, 0, size)
	setKey.right = make([]int, 0, size)
	setKey.privateKey = make([]*oaque.PrivateKey, 0, size)

	for i := 0; i < size; i++ {

		setKey.left = append(setKey.left, qualify.left[i])
		setKey.right = append(setKey.right, qualify.right[i])

		attrsTmp := newAttributeList(params, setKey.left[i], setKey.right[i], attrs)

		privateKey := &oaque.PrivateKey{}
		privateKey, err = oaque.QualifyKey(nil, params.params, qualify.privateKey[i], attrsTmp)
		if err != nil {
			return nil, err
		}

		setKey.privateKey = append(setKey.privateKey, privateKey)
	}
	return setKey, nil
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. lEnd and rEnd specify the leafID range to be delegated
func QualifyKey(params *Params, qualify *PrivateKey, attrs oaque.AttributeList, lEnd int, rEnd int) (*PrivateKey, error) {
	if !(*qualify.lEnd <= lEnd && rEnd <= *qualify.rEnd) {
		panic("Cannot generate key which is out bound of given key")
	}

	key := &PrivateKey{}

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd = lEnd
	*key.rEnd = rEnd

	key.setKey = make([]*privateKeyNode, rEnd-lEnd+1, rEnd-lEnd+1)

	// qualify.lEnd <= lEnd <= rEnd <= qualify.rEnd
	for i := lEnd; i <= rEnd; i++ {
		qualifyIndex := i - *qualify.lEnd
		keyIndex := i - lEnd
		for j := 0; j < len(qualify.setKey[qualifyIndex].privateKey); j++ {
			var err error
			key.setKey[keyIndex], err = qualifyKeyNode(params, qualify.setKey[qualifyIndex], attrs)
			if err != nil {
				return nil, err
			}
		}
	}

	key.attrs = make(oaque.AttributeList)
	for index := range attrs {
		key.attrs[index] = attrs[index]
	}

	return key, nil
}

func checkOutTwo(revocNode []bool, index int) bool {
	return (index == 1) || (revocNode[index<<1] && revocNode[(index<<1)+1])
}

func checkOutOne(revocNode []bool, index int) bool {
	return (revocNode[index<<1] && !revocNode[(index<<1)+1]) ||
		(!revocNode[index<<1] && revocNode[(index<<1)+1])
}

func newCipher(params *Params, vi int, vj int, attrs oaque.AttributeList, message *bn256.GT) (*Ciphertext, error) {
	var err error
	tmpCipher := &Ciphertext{}
	newAttrs := newAttributeList(params, vi, vj, attrs)
	tmpCipher.left, tmpCipher.right = new(int), new(int)
	*tmpCipher.left, *tmpCipher.right = vi, vj
	tmpCipher.cipher, err = oaque.Encrypt(nil, params.params, newAttrs, message)
	if err != nil {
		return nil, err
	}
	return tmpCipher, nil
}

func treeEncrypt(params *Params, attrs oaque.AttributeList, revocNode []bool, message *bn256.GT, revocSize int) (CiphertextList, error) {
	// Find all  [v_{i_1} ,v_{i_2} ,...v_{i_l}] where
	// (i) all of v_{i_1} ,v_{i_2} ,...v_{i_{l−1}} have outdegree 1 in ST(R)
	// (ii) v_{i_l} is either a leaf or a node with outdegree 2 and
	// (iii) the parent of v_{i_1} is either a node of outdegree 2 or the root.
	var cipher CiphertextList
	cipher = make(CiphertextList, 0, 2*revocSize-1)

	for i := 2; i < *params.userSize; i++ {
		if revocNode[i] == true && checkOutOne(revocNode, i) && checkOutTwo(revocNode, i>>1) {
			l := i
			for l < *params.userSize && !checkOutTwo(revocNode, l) {
				if revocNode[l<<1] {
					l <<= 1
				} else {
					l = (l << 1) + 1
				}
			}

			tmpCipher, err := newCipher(params, i, l, attrs, message)

			if err != nil {
				return nil, err
			}
			cipher = append(cipher, tmpCipher)
		}
	}
	return cipher, nil
}

// No function for revocation, since this is a stateless revocation scheme. User
// only need to specify revocation list along with URI during encryption.

// Encrypt first find sets which cover all the unrevoked leaves, and then
// encrypts message under those nodes' keys. The set covering algorithm used here
// is Subset Difference(SD).
func Encrypt(params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) (CiphertextList, error) {
	var ciphertext CiphertextList
	var err error

	if revoc == nil {
		ciphertext = make(CiphertextList, 0, 2)

		tmpCipher, err := newCipher(params, 1, 2, attrs, message)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, tmpCipher)

		tmpCipher, err = newCipher(params, 1, 3, attrs, message)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, tmpCipher)

		return ciphertext, nil
	}

	// ST(R): Find all node in the tree whose subtree contains revoked leaves.
	revocNode := make([]bool, 2*(*params.userSize), 2*(*params.userSize))

	for i := 1; i < 2*(*params.userSize); i++ {
		revocNode[i] = false
	}

	for i := 0; i < len(revoc); i++ {
		if revoc[i] <= 0 {
			panic("revoked id cannot be less than or equal to zero")
		}
		for index := leafIndex(*params.userSize, revoc[i]); index != 0; index >>= 1 {
			revocNode[index] = true
		}
	}

	ciphertext, err = treeEncrypt(params, attrs, revocNode, message, len(revoc))
	if err != nil {
		return nil, err
	}

	min, max := *params.userSize+1, 0
	for i := range revoc {
		if revoc[i] < min {
			min = revoc[i]
		}
		if max < revoc[i] {
			max = revoc[i]
		}
	}

	for min, max = leafIndex(*params.userSize, min), leafIndex(*params.userSize, max); min != max; {
		min >>= 1
		max >>= 1
	}

	if min != 1 {
		tmpCipher, err := newCipher(params, 1, min, attrs, message)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, tmpCipher)
	}

	return ciphertext, nil
}

func treeDecrypt(params *Params, pNode *privateKeyNode, cipher *Ciphertext, index int, attrs oaque.AttributeList) (*bn256.GT, error) {
	flag := false
	for i := index; i >= 1; i >>= 1 {
		if i == *cipher.right {
			break
		}
		if i == *cipher.left {
			flag = true
			break
		}
	}

	if !flag {
		return nil, nil
	}

	for i := *cipher.right; i != *cipher.left; i >>= 1 {
		for j := range pNode.privateKey {
			if pNode.left[j] == *cipher.left && pNode.right[j] == i {
				// NOTE: Qualify can be done within OAQUE.decrypt, but currently do not support that
				var tmpKey *oaque.PrivateKey
				var tmpAttrs oaque.AttributeList
				var err error

				if pNode.right[j] != *cipher.right {
					tmpAttrs = newAttributeList(params, *cipher.left, *cipher.right, attrs)

					tmpKey, err = oaque.QualifyKey(nil, params.params, pNode.privateKey[j], tmpAttrs)
					if err != nil {
						return nil, err
					}
				} else {
					tmpKey = pNode.privateKey[j]
				}

				return oaque.Decrypt(tmpKey, cipher.cipher), nil
			}
		}
	}
	return nil, nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(params *Params, key *PrivateKey, ciphertext CiphertextList) *bn256.GT {
	var plaintext *bn256.GT
	var err error

	for i := 0; i < len(ciphertext); i++ {
		for j := *key.lEnd; j <= *key.rEnd; j++ {
			plaintext, err = treeDecrypt(params, key.setKey[j-*key.lEnd], ciphertext[i], leafIndex(*params.userSize, j), key.attrs)
			if err != nil {
				panic("Cannot qualify key during decryption")
			}
			if plaintext != nil {
				return plaintext
			}
		}
	}
	return nil
}
