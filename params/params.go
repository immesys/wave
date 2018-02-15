package params

//The oaque keys are used for the
//pdots, and for namespace E2EE
//This value cannot really be changed once
//things get going
const OAQUESlots = 21

const LocationUC = "eth://4514?storage=swarm"

const OidPrefix = "2.25.45143053631457624761134634438852551742"

const OidEntity = "2.25.45143053631457624761134634438852551742.1"
const OidDot = "2.25.45143053631457624761134634438852551742.2"

type engineContextKey string

var PerspectiveKey engineContextKey = "perspective"
