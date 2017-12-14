

function checksigners() {
var lat = eth.getBlock("latest")


var res = {}
var cn = clique.getSnapshot()
for (var sig in cn.signers) {
  res[sig] = 0
}
for (var bn = lat.number - 100; bn < lat.number; bn++) {
  var bl = eth.getBlock(bn)
  var c = clique.getSnapshotAtHash(bl.hash)
  var signer = c.recents[bn]
  res[signer] += 1
}
return res
}
