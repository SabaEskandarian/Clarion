package mycrypto

import (
    "log"
    "crypto/rand"
    "crypto/aes"
    "crypto/cipher"
    //"golang.org/x/crypto/nacl/box"
    //"strings"
    "bytes"
    
    "shufflemessage/modp"
)

//Generates a ciphertext under a random key and returns the ct with key appended
func MakeCT(numBlocks int) []byte {
    
    blockSize := 16
    dataLen := numBlocks * blockSize
    
    //make up a message to encrypt, set empty iv
    m := make([]byte, dataLen)
    for i := 0; i < dataLen; i++ {
        m[i] = 'a'
    }
    zeroIV := make([]byte, blockSize)
    
    //generate a random encryption key
    
    key := make([]byte, 16)
    _,err := rand.Read(key)
    if err != nil {
        log.Println("couldn't generate key")
        panic(err)
    }
    
    //use the key to encrypt the message
    c, err := aes.NewCipher(key)
    if err != nil {
        log.Println("Couldn't inititate new cipher")
        panic(err)
    }
    ctr := cipher.NewCTR(c, zeroIV)
    ct := make([]byte, dataLen)
    ctr.XORKeyStream(ct, m)
    //ct now holds the encrypted message
    
    ct = append(ct, key...)
    
    return ct
}

//decrypt ct where first 16 bytes are the AES key, zero IV
func DecryptCT(ct []byte) []byte{
    
    plaintext := make([]byte, len(ct) - 16)
    zeroIV := make([]byte, 16)
    
    c, err := aes.NewCipher(ct[:16])
    if err != nil {
        log.Println("Couldn't inititate new cipher")
        panic(err)
    }
    ctr := cipher.NewCTR(c, zeroIV)
    ctr.XORKeyStream(plaintext, ct[16:])
    
    return plaintext
}

//outputs a mac on the msg and a key share seed for each server
func WeirdMac(numServers int, msg []byte) ([]byte, [][]byte) {
    
    msgLen := len(msg)
    
    //generate key shares
    keyShareSeeds := make([][]byte, numServers)
    for i := 0; i < numServers; i++ {
        keyShareSeeds[i] = make([]byte, 16)
        _,err := rand.Read(keyShareSeeds[i])
        if err != nil {
            log.Println("wasn't able to generate a MAC key share seeds")
            panic(err)
        }
    }
    
    //expand seeds to actual key shares using AES in CTR mode as PRG
    keyShares := make([][]byte, numServers)
    for i:= 0; i < numServers; i++ {
        keyShares[i] = AesPRG(msgLen, keyShareSeeds[i])
    }
    
    return ComputeMac(msg, keyShares), keyShareSeeds
}

//compute MAC in the clear
func ComputeMac(msg []byte, keyShares [][]byte) []byte {
    
    numServers := len(keyShares)
    msgBlocks := len(msg) / 16
    if len(msg) % 16 != 0 {
        panic("msgLen isn't a multiple of block size. Something has gone wrong :(")
    }
    
    var mac, keyPiece, msgPiece, product modp.Element
    for i:=0; i < msgBlocks; i++ {
        msgPiece.SetBytes(msg[16*i:16*(i+1)])
        
        for j:=0; j < numServers; j++ {
            keyPiece.SetBytes(keyShares[j][16*i:16*(i+1)])
            product.Mul(&keyPiece, &msgPiece)
            mac.Add(&mac, &product)
        }
    }
    
    return mac.Bytes()
}

//check mac in the clear
func CheckMac(msg, tag []byte, keyShares [][]byte) bool {
    return bytes.Equal(ComputeMac(msg, keyShares), tag)
}

//expand a seed using aes in CTR mode
func AesPRG(msgLen int, seed []byte) []byte {
    
    empty := make([]byte, msgLen)
    
    //use the key to encrypt the message
    c, err := aes.NewCipher(seed)
    if err != nil {
        log.Println("Couldn't inititate new cipher")
        panic(err)
    }
    ctr := cipher.NewCTR(c, empty[:16])
    ct := make([]byte, msgLen)
    ctr.XORKeyStream(ct, empty)
    //ct now holds the encrypted message
    
    return ct
}

//splits a message into additive shares mod a prime
func Share(numShares int, msg []byte) [][]byte {
    shares := make([][]byte, numShares)
    shares[0] = make([]byte, len(msg))
    
    numBlocks := len(msg)/16
    if len(msg) % 16 != 0 {
        panic("message being shared has length not a multiple of 16")
    }
        
    var lastShare []*modp.Element

    //make lastShare hold msg in Element form
    for i:= 0; i < numBlocks; i++ {
        var temp modp.Element
        lastShare = append(lastShare, temp.SetBytes(msg[16*i:16*(i+1)]))
    }
    
    
    for i:= 1; i < numShares; i++ {
                
        //make the share random
        shares[i] = make([]byte, len(msg))
        _,err := rand.Read(shares[i])
        if err != nil {
            log.Println("couldn't generate randomness for sharing")
            panic(err)
        }
        
        //change every 16-byte block into an Element
        //subtract from the last share
        for j:=0; j < numBlocks; j++ {
            var temp modp.Element
            lastShare[j].Sub(lastShare[j], temp.SetBytes(shares[i][16*j:16*(j+1)]))
        }
    }
    
    //set the zeroth share to be lastShare in byte form
    for i:=0; i < numBlocks; i++ {
        copy(shares[0][16*i:16*(i+1)], lastShare[i].Bytes())
    }
    
    return shares
}

//generate beaver triples
//outputs are slices for values of a, b, c for each server
//func GenBeavers(numBeavers, numServers int) ([][]byte, [][]byte, [][]byte) {
    //TODO
//}

//TODO generate permutations and share translations
//func GenShareTrans(vecLen, numServers int)
