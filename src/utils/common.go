package utils

import (
	"time"
)


func ReverseBytes(s []byte) []byte{
   for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
        s[i], s[j] = s[j], s[i]
    }
    return s
}

func GetCurrentUnixTimeStamp() uint32 {
    timestamp := time.Now().Unix()
    return uint32(timestamp)
}





