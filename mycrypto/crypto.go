package mycrypto

import (
    "log"
    "crypto/rand"
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    //"golang.org/x/crypto/nacl/box"
    //"strings"
    "bytes"
    
    "shufflemessage/modp"
)

//Generates a ciphertext under a random key and returns the ct with key prepended
func MakeCT(numBlocks, msgType int) []byte {
    
    blockSize := 16
    dataLen := numBlocks * blockSize
    
    //make up a message to encrypt, set empty iv
    m := make([]byte, dataLen)
    for i := 0; i < dataLen; i++ {
        m[i] = byte(97 + msgType) //ascii 'a' is 97
    }
    zeroIV := make([]byte, blockSize)
    
    //generate a random encryption key
    
    key := make([]byte, 16)
    _,err := rand.Read(key)
    if err != nil {
        log.Println("couldn't generate key")
        panic(err)
    }
    //log.Println(key)
    
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
    
    ct = append(key, ct...)
    
    return ct
}

//decrypt ct where first 16 bytes are the AES key. use zero IV
func DecryptCT(ct []byte) []byte{
    
    plaintext := make([]byte, len(ct) - 16)
    zeroIV := make([]byte, 16)
    
    //log.Println(ct[:16])
    
    c, err := aes.NewCipher(ct[:16])
    if err != nil {
        log.Println("Couldn't initiate new cipher")
        panic(err)
    }
    ctr := cipher.NewCTR(c, zeroIV)
    ctr.XORKeyStream(plaintext, ct[16:])
    
    return plaintext
}

//outputs a mac on the msg and a key share seed for each server
func WeirdMac(numServers int, msg []byte) ([]byte, [][]byte) {
        
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
    
    return ComputeMac(msg, keyShareSeeds), keyShareSeeds
}

//compute MAC in the clear
func ComputeMac(msg []byte, keyShareSeeds [][]byte) []byte {
    
    numServers := len(keyShareSeeds)
    msgLen := len(msg)
    msgBlocks := msgLen / 16
    if len(msg) % 16 != 0 {
        panic("msgLen isn't a multiple of block size. Something has gone wrong :(")
    }
    
    //expand seeds to actual key shares using AES in CTR mode as PRG
    keyShares := make([][]byte, numServers)
    for i:= 0; i < numServers; i++ {
        keyShares[i] = AesPRG(msgLen, keyShareSeeds[i])
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
func CheckMac(msg, tag []byte, keyShareSeeds [][]byte) bool {
    return bytes.Equal(ComputeMac(msg, keyShareSeeds), tag)
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

//expand a key seed share to a vector of zeros with the seed in the correct place
func ExpandKeyShares(myServerNum, numServers int, keySeedShare []byte) []byte {
    expansion := make([]byte, 16*numServers)
    copy(expansion[16*myServerNum:16*(myServerNum+1)], keySeedShare)
    return expansion
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

//combine additive shares to recover message
func Merge(shares [][]byte) []byte{

    numShares := len(shares)
    numBlocks := len(shares[0])/16
    if len(shares[0]) % 16 != 0 {
        panic("messages being merged have length not a multiple of 16")
    }
    
    var elements []*modp.Element

    //make array of elements that holds the first share
    for j:=0; j < numBlocks; j++ {
        var temp modp.Element
        elements = append(elements, temp.SetBytes(shares[0][16*j:16*(j+1)]))
    }
    
    //add in the corresponding elements from subsequent shares
    for i:=1; i < numShares; i++ {
        if len(shares[i]) != len(shares[0]) {
            panic("messages being merged have different lengths")
        }
        
        var temp modp.Element
        
        for j:=0; j < numBlocks; j++ {
            temp.SetBytes(shares[i][16*j:16*(j+1)])
            elements[j].Add(elements[j], &temp)
        }
    }
    
    //convert the whole thing to []byte
    output := make([]byte, 0)
    for j:=0; j < numBlocks; j++ {
        output = append(output, elements[j].Bytes()...)
    }
    
    return output
}

//generate a permutation of the numbers [0, n)
//NOTE: can this be made faster?
//e.g., by statically allocating a bit perm instead of making a new slice each time?
func GenPerm(n int) []int {
    perm := make([]int, n)
    var randNum [4]byte
    
    for i:=1; i < n; i++ {
        _,err := rand.Read(randNum[:])
        if err != nil {
            panic("randomness issue")
        }
        j := byteToInt(randNum[:]) % (i+1)
        perm[i] = perm[j]
        perm[j] = i
    }
    return perm
}

func byteToInt(myBytes []byte) (x int) {
    x = int(myBytes[3]) << 24 + int(myBytes[2]) << 16 + int(myBytes[1]) << 8 + int(myBytes[0])
    return
}

func intToByte(myInt int) (retBytes []byte){
    retBytes = make([]byte, 4)
    retBytes[3] = byte((myInt >> 24) & 0xff)
    retBytes[2] = byte((myInt >> 16) & 0xff)
    retBytes[1] = byte((myInt >> 8) & 0xff)
    retBytes[0] = byte(myInt & 0xff)
    return
}

//generate beaver triples
//outputs are [][]byte slices for each server that contain [a]||[b]||[c] (in beaverDB)
func GenBeavers(numBeavers, numServers int) [][]byte {
    
    triples := make([]byte, numBeavers*48)
    var eltA, eltB, eltC modp.Element
    
    //generate triples a,b,c s.t. a*b=c
    for i:= 0; i < numBeavers; i++ {
        
        //generate random A, B, multiply to get C
        start:= i*48
        
        _,err := rand.Read(triples[start:start+32])
        if err != nil {
            panic("randomness issue in beaver triple generation")
        }

        eltA.SetBytes(triples[start:start+16])
        eltB.SetBytes(triples[start+16:start+32])
        eltC.Mul(&eltA, &eltB)
        copy(triples[start+32:start+48], eltC.Bytes())
    }
    
    //NOTE: could probably speed this up a little by skipping a bunch of []byte->Element->[]byte conversions and just doing the secret sharing on the Elements directly
    
    //share the beaver triples
    return Share(numServers, triples)
}

//generate permutations and share translations
//returns a permutation for each server (first return value)
//as well as a Delta for each permutation (second return value)
//and a,b for each server for each permutation (third return value)
func GenShareTrans(batchSize, blocksPerRow, numServers int) ([][]byte, [][]byte, [][][]byte) {
    
    //perms is made of bytes so it can be transmitted easily
    perms := make([][]byte, numServers)
    abs := make([][][]byte, numServers)
    deltas := make([][]byte, numServers)
        
    var pia,b,d modp.Element
    
    //length of a,b,d
    length := batchSize*blocksPerRow*16
    
    for i := 0; i < numServers; i++ {
        
        //generate permutation
        perm := GenPerm(batchSize)
                
        //make the byte version of perm too
        perms[i] = make([]byte, 0)
        for j := 0; j < batchSize; j++ {
            perms[i] = append(perms[i], intToByte(perm[j])...)
        }
        
        //generate a, b
        abs[i] = make([][]byte, numServers)
        for j := 0; j < numServers; j++ {
            abs[i][j] = make([]byte, 2*length)
            
            //when server i is permuting, all servers j != i get a,b
            if i != j {
                _,err := rand.Read(abs[i][j])
                if err != nil {
                    panic("randomness issue in share translation generation")
                }
            }            
        }
        
        //generate delta
        deltas[i] = make([]byte, length)
        //for every block of data in the db
        for j := 0; j < batchSize; j++ {
            for c:= 0; c < blocksPerRow; c++ {
                //for each server's share
                for k := 0; k < numServers; k++ {
                    if k != i {
                        //set d = \pi(a)-b
                        currBlockNum := j*blocksPerRow+c
                        permutedBlockNum := perm[j]*blocksPerRow+c
                        pia.SetBytes(abs[i][k][permutedBlockNum*16:(permutedBlockNum+1)*16])
                        b.SetBytes(abs[i][k][length+(currBlockNum)*16:length+(currBlockNum+1)*16])
                        copy(deltas[i][currBlockNum*16:(currBlockNum+1)*16], d.Sub(&pia, &b).Bytes())
                    }
                }
            }
        }
    }
    
    return perms, deltas, abs
}

//flatten and compute a hash of the db
func FlattenAndHash(db [][]byte) ([]byte, []byte) {
    
    flatDB := make([]byte, 0)
    
    for i:= 0; i < len(db); i++ {
        flatDB = append(flatDB, db[i]...)
    }
    
    hash := sha256.Sum256(flatDB)
    return flatDB, hash[:]
}

//NOTE: could use a goroutine to check hashes in parallel
//check hashes of many flat DBs
func CheckHashes(hashes, dbs []byte, dbLen int) bool {
    for i:=0; i < len(hashes)/32; i++ {
        hash := sha256.Sum256(dbs[dbLen*i:dbLen*(i+1)])
        if !bytes.Equal(hashes[32*i:32*(i+1)], hash[:]) {
            return false
        }
    }
    return true
}
