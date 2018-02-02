package csroaque

import (
	"io"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

type paramsNode struct {
	left   *paramsNode
	right  *paramsNode
	params *oaque.Params
}

type Params struct {
	userSize *int
	root     *paramsNode
}

type masterKeyNode struct {
	left      *masterKeyNode
	right     *masterKeyNode
	masterKey *oaque.MasterKey
}

//	This should be out of band, and managed by namespace
//	userNumber *int

type MasterKey struct {
	root *masterKeyNode
}

type privateKeyNode struct {
	left       *privateKeyNode
	right      *privateKeyNode
	privateKey *oaque.PrivateKey
}

//	PrivateKey is a subtree in BEtree(note that this subtree might not be a Complete Binary Tree)
type PrivateKey struct {
	root       *privateKeyNode
	lEnd, rEnd *int
}

type RevocationList []int

type Ciphertext struct {
	cipher     *oaque.Ciphertext
	lEnd, rEnd *int
}

type CiphertextList []*Ciphertext

func BuildBEtree(random io.Reader, l int, left int, right int) (*paramsNode, *masterKeyNode, error) {
	if left > right {
		return nil, nil, nil
	}

	pNode := &paramsNode{}
	mNode := &masterKeyNode{}
	var err error

	pNode.params, mNode.masterKey, err = oaque.Setup(random, l)
	if err != nil {
		return nil, nil, err
	}

	if left == right {
		pNode.left, pNode.right, mNode.left, mNode.right = nil, nil, nil, nil
		return pNode, mNode, nil
	}
	mid := (left + right) / 2 // make sure this is div
	pNode.left, mNode.left, err = BuildBEtree(random, l, left, mid)
	if err != nil {
		return nil, nil, err
	}

	pNode.right, mNode.right, err = BuildBEtree(random, l, mid+1, right)
	if err != nil {
		return nil, nil, err
	}

	return pNode, mNode, nil
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 1 to l-1). The parameter	"n" is the total number of users
// supported(indexed from 1 to n).
func Setup(random io.Reader, l int, n int) (*Params, *MasterKey, error) {
	params := &Params{}
	masterKey := &MasterKey{}
	var err error

	params.userSize = new(int)
	*params.userSize = n

	//	masterKey.userNumber = new(int)
	//	*masterKey.userNumber = n

	params.root, masterKey.root, err = BuildBEtree(random, l, 1, n)
	if err != nil {
		return nil, nil, err
	}

	//	params.revocationList = make([]int, 0, n)

	return params, masterKey, nil
}

func treeKeyGen(pNode *paramsNode, mNode *masterKeyNode, left int, right int, lEnd int, rEnd int, attrs oaque.AttributeList) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	var err error
	node := &privateKeyNode{}

	// nil for random on the fly
	node.privateKey, err = oaque.KeyGen(nil, pNode.params, mNode.masterKey, attrs)
	if err != nil {
		return nil, err
	}

	if left == right {
		node.left, node.right = nil, nil
		return node, nil
	}

	mid := (left + right) / 2 // Note: it should be div

	node.left, err = treeKeyGen(pNode.left, mNode.left, left, mid, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}

	node.right, err = treeKeyGen(pNode.right, mNode.right, mid+1, right, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}

	return node, err
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
	key.root, err = treeKeyGen(params.root, master.root, 1, *params.userSize, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd, *key.rEnd = lEnd, rEnd
	return key, nil
}

func treeQualifyKey(pNode *paramsNode, qNode *privateKeyNode, left int, right int, lEnd int, rEnd int, attrs oaque.AttributeList) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	if qNode == nil {
		return nil, nil
	}

	var err error
	node := &privateKeyNode{}

	// nil for random on the fly
	node.privateKey, err = oaque.QualifyKey(nil, pNode.params, qNode.privateKey, attrs)
	if err != nil {
		return nil, err
	}

	if left == right {
		node.left, node.right = nil, nil
		return node, nil
	}

	mid := (left + right) / 2 // Note: it should be div

	node.left, err = treeQualifyKey(pNode.left, qNode.left, left, mid, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}

	node.right, err = treeQualifyKey(pNode.right, qNode.right, mid+1, right, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}

	return node, err
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. lEnd and rEnd specify the leafID range to be delegated
func QualifyKey(params *Params, qualify *PrivateKey, attrs oaque.AttributeList, lEnd int, rEnd int) (*PrivateKey, error) {
	if !(*qualify.lEnd <= lEnd && rEnd <= *qualify.rEnd) {
		panic("Cannot generate key out bound of given key")
	}

	key := &PrivateKey{}
	var err error

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd = lEnd
	*key.rEnd = rEnd

	key.root, err = treeQualifyKey(params.root, qualify.root, 1, *params.userSize, lEnd, rEnd, attrs)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func treeEncrypt(pNode *paramsNode, left int, right int, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) (CiphertextList, error) {
	if left > right {
		return nil, nil
	}

	if pNode == nil {
		return nil, nil
	}

	flag := false
	// This check can be reduced to O(log r), if we build segment tree on top of RevocationList
	for i := range revoc {
		if left <= revoc[i] && revoc[i] <= right {
			flag = true
			break
		}
	}

	if !flag {
		var cipher CiphertextList
		cipher = make(CiphertextList, 1, 1)
		cipher[0] = new(Ciphertext)
		var err error
		cipher[0].cipher, err = oaque.Encrypt(nil, pNode.params, attrs, message)
		if err != nil {
			return nil, err
		}
		cipher[0].lEnd, cipher[0].rEnd = new(int), new(int)
		*cipher[0].lEnd, *cipher[0].rEnd = left, right

		return cipher, nil
	}

	var err error
	var cipherLeft, cipherRight CiphertextList
	mid := (left + right) / 2 // note should be div
	cipherLeft, err = treeEncrypt(pNode.left, left, mid, attrs, revoc, message)
	if err != nil {
		return nil, err
	}

	cipherRight, err = treeEncrypt(pNode.right, mid+1, right, attrs, revoc, message)
	if err != nil {
		return nil, err
	}

	cipher := make(CiphertextList, 0, len(cipherLeft)+len(cipherRight))
	cipher = append(cipher, cipherLeft...)
	cipher = append(cipher, cipherRight...)

	return cipher, nil
}

// No function for revocation, since this is a stateless revocation scheme. User
// only need to specify revocation list along with URI during encryption.

// Encrypt first find a node set which cover all the unrevoked leaves, and then
// encrypts message under those nodes' keys. The set covering algorithm used here
// is Complete Tree(CS)
func Encrypt(params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) (CiphertextList, error) {
	//TODO empty revoc
	var ciphertext CiphertextList
	var err error
	ciphertext, err = treeEncrypt(params.root, 1, *params.userSize, attrs, revoc, message)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func treeDecrypt(pNode *privateKeyNode, left int, right int, ciphertext CiphertextList) *bn256.GT {
	if left > right {
		return nil
	}

	if pNode == nil {
		return nil
	}
	// This can be optimized to O(1).
	for i := range ciphertext {
		if left == *ciphertext[i].lEnd && right == *ciphertext[i].rEnd {
			plaintext := oaque.Decrypt(pNode.privateKey, ciphertext[i].cipher)
			return plaintext
		}
	}

	var plaintext *bn256.GT
	mid := (left + right) / 2
	plaintext = treeDecrypt(pNode.left, left, mid, ciphertext)
	if plaintext != nil {
		return plaintext
	}
	plaintext = treeDecrypt(pNode.right, mid+1, right, ciphertext)
	if plaintext != nil {
		return plaintext
	}

	return nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(params *Params, key *PrivateKey, ciphertext CiphertextList) *bn256.GT {
	plaintext := treeDecrypt(key.root, 1, *params.userSize, ciphertext)
	return plaintext
}
