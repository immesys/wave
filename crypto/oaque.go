package crypto

import (
	"crypto/rand"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

func GenerateOAQUEKeys() (*oaque.Params, *oaque.MasterKey, error) {
	p, m, e := oaque.Setup(rand.Reader, 20)
	return p, m, e
}
