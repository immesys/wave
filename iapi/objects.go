package iapi

import "github.com/immesys/wave/serdes"

type InEntity struct {
	//This would be a WaveEntitySecret or nil
	secret *serdes.WaveWiredObject
	//This is always present
	public *serdes.WaveWiredObject
}

func (ie *InEntity) EntitySecret() {

}
