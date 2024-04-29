package mining

import (

	"github.com/humblenginr/btc-miner/utils"
)

func GenerateMerkleTreeRoot(txids [][32]byte) [32]byte{
  // reverse the txids
    level := make([][32]byte, 0)
    for _, t := range txids {
        level = append(level, [32]byte(utils.ReverseBytes(t[:])))
    }

    for len(level) > 1 {
    nextLevel := make([][32]byte, 0)

    for i := 0; i < len(level); i += 2 {
      var pairHash [32]byte
      if (i + 1 == len(level)) {
        // In case of an odd number of elements, duplicate the last one
        var x [64]byte
        copy(x[:32], level[i][:])
        copy(x[32:], level[i][:])
        pairHash = utils.DoubleHashRaw(x[:])
      } else {
        var x [64]byte
        copy(x[:32], level[i][:])
        copy(x[32:], level[i+1][:])
        pairHash = utils.DoubleHashRaw(x[:])
      }
            nextLevel = append(nextLevel, pairHash)
    }

    level = nextLevel
  }

  return level[0]
}

