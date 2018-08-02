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

//Granting this permission with the wave builtin pset allows the recipient
//to decrypt end-to-end encrypted messages
var WaveBuiltinE2EE = "decrypt"
