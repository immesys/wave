
var caddr = "0x5a76921D67b863E7d6c77ACfe1307D2ACEdd9007"
var ptld = "aabbcc0000000000000000000000000000000000000000000000000000000000"
var psubdomain = "2200000000000000000000000000000000000000000000000000000000000000"
var pdomain =    "1100000000000000000000000000000000000000000000000000000000000000"

var TLDObject = web3.sha3(ptld + "0000000000000000000000000000000000000000000000000000000000000000", {encoding:"hex"})
// ^ 0x36a849ff4f869fbaa1a3e8daf2e068e6b148dcb155313fa71f0d8e718c8dc048
console.log("controller",eth.getStorageAt(caddr, TLDObject))
var baseOfDomainToDomainObject = "36a849ff4f869fbaa1a3e8daf2e068e6b148dcb155313fa71f0d8e718c8dc049"
var DomainObject = web3.sha3(pdomain+baseOfDomainToDomainObject, {encoding:"hex"})
console.log("domainobject",DomainObject)
// ^ 0xacfe3342396a14674639ac64319ed5b7d9334ebaf097b2746405a260b4c2cf57
var baseOfSubdomainToSubdomainObject = "acfe3342396a14674639ac64319ed5b7d9334ebaf097b2746405a260b4c2cf58"
var SubdomainObject = web3.sha3(psubdomain + baseOfSubdomainToSubdomainObject, {encoding:"hex"})
console.log("subdomain addr",SubdomainObject)

var domain = web3.sha3(tld + "0000000000000000000000000000000000000000000000000000000000000000", {encoding:"hex"})
// ^ this was 0x36a849ff4f869fbaa1a3e8daf2e068e6b148dcb155313fa71f0d8e718c8dc048
var domainp1 = "0x36a849ff4f869fbaa1a3e8daf2e068e6b148dcb155313fa71f0d8e718c8dc049"
//This is the base of the map to domain
var domainentry = web3.sha3(pdomain +domainp1, {"encoding":"hex"})
console.log("domainentry:",domainentry)
//This is the base of the map from subdomain -> value
var domainentryp1="0x25c84425fc8986d3218ed7c32140236b721d333213488383aac0ea102376e6bd"

/* var getHead = function(tld, subdomain) {
   var domain = web3.sha3(tld + "0000000000000000000000000000000000000000000000000000000000000000", {encoding:"hex"})
   console.log("domain1 is",domain)
   var domainNumber = web3.toBigNumber(domain);
   console.log(
   var domainHex = web3.toHex(domainNumber);
   console.log("domain2 is",domainHex)
 }
*/
