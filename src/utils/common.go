package utils

import "crypto/sha256"

func DoubleHash(b []byte) []byte {
    return Hash(Hash(b))
}

func Hash(b []byte) []byte {
    h := sha256.New()
    h.Write(b)
    return h.Sum(nil)
}

func ReverseBytes(s []byte) []byte{
   for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
    return s
}
