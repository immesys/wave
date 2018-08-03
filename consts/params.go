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

//Granting this permission with the wave builtin pset allows the recipient
//to decrypt end-to-end encrypted messages
var WaveBuiltinE2EE = "decrypt"
