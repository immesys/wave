package consts

//The oaque keys are used for the
//pdots, and for namespace E2EE
//This value cannot really be changed once
//things get going
const OAQUESlots = 21

type constContextKey string

var PerspectiveKey constContextKey = "perspective"

//This is the wave built-in permission set, the hash of "wavebuiltin"
var WaveBuiltinPSET = "GyAZSVTobuuPkf-YOsxW5shK4pqQfOfnY46GV9UUmbGIpA=="
var WaveBuiltinPSETBytes = "\x1b\x20\x19\x49\x54\xe8\x6e\xeb\x8f\x91\xff\x98\x3a\xcc\x56\xe6\xc8\x4a\xe2\x9a\x90\x7c\xe7\xe7\x63\x8e\x86\x57\xd5\x14\x99\xb1\x88\xa4"

//The hash of "$GLOBAL"
var WaveGlobalNamespace = "GyDPjRnXnSMBOGW-91fOoEze5e9O3vyAjdIeTgBeb4BHzA=="
var WaveGlobalNamespaceBytes = "\x1b\x20\xcf\x8d\x19\xd7\x9d\x23\x01\x38\x65\xbe\xf7\x57\xce\xa0\x4c\xde\xe5\xef\x4e\xde\xfc\x80\x8d\xd2\x1e\x4e\x00\x5e\x6f\x80\x47\xcc"

var WAVEMQPSETBytes = "\x1b\x20\x14\x33\x74\xb3\x2f\xd2\x74\x39\x54\xfe\x47\x86\xf6\xcf\x86\xd4\x03\x72\x0f\x5e\xc4\x42\x36\xb6\x58\xc2\x6a\x1e\x68\x0f\x6e\x01"

//Granting this permission with the wave builtin pset allows the recipient
//to decrypt end-to-end encrypted messages
var WaveBuiltinE2EE = "decrypt"

// This is the JEDI built-in permission set.
var JEDIBuiltinPSET = "GyAdzlOf-YTN8eq9Fw0-S0XQ_Lh2KL0HCBrDQTvqiDe88A=="
var JEDIBuiltinPSETByteArray = []byte{27, 32, 29, 206, 83, 159, 249, 132, 205, 241, 234, 189, 23, 13, 62, 75, 69, 208, 252, 184, 118, 40, 189, 7, 8, 26, 195, 65, 59, 234, 136, 55, 188, 240}
var JEDIBuiltinDecrypt = "decrypt"
var JEDIBuiltinSign = "sign"

//This can actually be changed
var DefaultToUnrevoked = false
