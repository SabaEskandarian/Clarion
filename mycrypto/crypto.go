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

func AddOrSub(a, b []byte, add bool) {
    var eltA, eltB modp.Element
    for i :=0; i < len(a)/16; i++ {
        eltA.SetBytes(a[16*i:16*(i+1)])
        eltB.SetBytes(b[16*i:16*(i+1)])
        
        if add {
            eltA.Add(&eltA, &eltB)
        } else {
            eltA.Sub(&eltA, &eltB)
        }
        
        copy(a[16*i:16*(i+1)], eltA.Bytes())
    }
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

func TestGenBeavers() bool {
    numBeavers := 3
    numServers := 2
    
    beavers := Merge(GenBeavers(numBeavers, numServers))
    
    var a, b, c, prod modp.Element
    for i:=0; i < numBeavers; i++ {
        startBeaver := i*48
        a.SetBytes(beavers[startBeaver:startBeaver+16])
        b.SetBytes(beavers[startBeaver+16:startBeaver+32])
        c.SetBytes(beavers[startBeaver+32:startBeaver+48])
        prod.Mul(&a, &b)
        prod.Sub(&prod,&c)
        if !prod.IsZero() {
            log.Println(i)
            return false
        }
    }
    
    return true
}

//generate permutations and share translations
//returns:
//a permutation for each server 
// a Delta for each server
// initial masks a for each server
// masks a for each server after they permute
// an output b for each server from the last permutation
// a value s that preprocesses input shares for each server's permutation
func GenShareTrans(batchSize, blocksPerRow, numServers int) ([][]byte, [][]byte, [][]byte, [][]byte, [][]byte, [][]byte) {
    
    //perms is made of bytes so it can be transmitted easily
    perms := make([][]byte, numServers)
    aInitial := make([][]byte, numServers)
    aAtPermTime := make([][]byte, numServers)
    bFinal := make([][]byte, numServers)
    sAtPermTime := make([][]byte, numServers)
    deltas := make([][]byte, numServers)

    //length of db
    length := batchSize*blocksPerRow*16

    for i := 0; i < numServers; i++ {
        
        //generate permutation
        perm := GenPerm(batchSize)
                
        //make the byte version of perm too
        perms[i] = make([]byte, 0)
        for j := 0; j < batchSize; j++ {
            perms[i] = append(perms[i], intToByte(perm[j])...)
        }
        
        //initialize stuff
        //aInitial[i] = make([]byte, length)
        //aAtPermTime[i] = make([]byte, length)
        //bFinal[i] = make([]byte, length)
        sAtPermTime[i] = make([]byte, length)
        deltas[i] = make([]byte, length)
    }
    
    for timeStep := 0; timeStep < numServers; timeStep++ {
        for server := 0; server < numServers; server++ {
            randA := make([]byte, length)
            randB := make([]byte, length)
            _,err := rand.Read(randA)
            if err != nil {
                panic("randomness issue in share translation generation")
            }
            _,err = rand.Read(randB)
            if err != nil {
                panic("randomness issue in share translation generation")
            }
            
            if timeStep == 0 && server != 0 {
                aInitial[server] = randA
            }
            if timeStep == numServers - 1 && server != numServers -1 {
                bFinal[server] = randB
            }
            if timeStep == server+1 {
                aAtPermTime[server] = randA
            }
                        
            var perma, a, b, aggregate modp.Element
            for i:=0; i < blocksPerRow*batchSize; i++ {
                currRow := i/blocksPerRow
                currRowIndex := i%blocksPerRow
                permRow := byteToInt(perms[timeStep][4*currRow:4*(currRow+1)])
                permutedI := permRow*blocksPerRow+currRowIndex
                
                a.SetBytes(randA[16*i:16*(i+1)])
                perma.SetBytes(randA[16*permutedI:16*(permutedI+1)])
                b.SetBytes(randB[16*i:16*(i+1)])
                
                if timeStep != server {
                    aggregate.SetBytes(deltas[timeStep][16*i:16*(i+1)])
                    aggregate.Add(&aggregate, &perma)
                    aggregate.Sub(&aggregate, &b)
                    copy(deltas[timeStep][16*i:16*(i+1)], aggregate.Bytes())
                }

                                
                //sAtPermTime
                if timeStep != numServers-1 && timeStep != server {
                    aggregate.SetBytes(sAtPermTime[timeStep+1][16*i:16*(i+1)])
                    aggregate.Add(&aggregate, &b)
                    copy(sAtPermTime[timeStep+1][16*i:16*(i+1)], aggregate.Bytes())
                }
                
                if timeStep != 0 && timeStep != server && timeStep != server+1 {
                    aggregate.SetBytes(sAtPermTime[timeStep][16*i:16*(i+1)])
                    aggregate.Sub(&aggregate, &a)
                    copy(sAtPermTime[timeStep][16*i:16*(i+1)], aggregate.Bytes())
                }
                
            }
        }
    }

    return perms, aInitial, aAtPermTime, bFinal, sAtPermTime, deltas
}

func TestGenShareTrans() bool {
    
    //batchSize 10, blocks per row 5, numServers 2
    perms, aInitial, aAtPermTime, bFinal, sAtPermTime, deltas := GenShareTrans(10, 5, 2)
    
    pis := make([][]int, 2)
    pis[0] = make([]int, 0)
    pis[1] = make([]int, 0)
    for i:=0; i < 10; i++ {
        pis[0] = append(pis[0], byteToInt(perms[0][4*i:4*(i+1)]))
        pis[1] = append(pis[1], byteToInt(perms[1][4*i:4*(i+1)]))

    }
    //log.Println(pis[0])
    //log.Println(pis[1])

    flatDB := make([]byte, 50*16)
    
    //make aInitial values negative
    AddOrSub(flatDB, aInitial[1], false)
    
    flatDB = permuteDB(flatDB, pis[0])
    
    AddOrSub(flatDB, deltas[0], true)
    
    AddOrSub(flatDB, aAtPermTime[0], false)
    
    //server 1 starts here
    AddOrSub(flatDB, sAtPermTime[1], true)
    
    flatDB = permuteDB(flatDB, pis[1])
        
    AddOrSub(flatDB, deltas[1], true)
    
    AddOrSub(flatDB, bFinal[0], true)
    
    zero := make([]byte, 50*16)
    
    return bytes.Equal(flatDB, zero)
}

//just used for internal testing
func permuteDB(flatDB []byte, pi []int) []byte{
    rowLen := len(flatDB)/len(pi)

    permutedDB := make([]byte, len(flatDB))
    

    //permute
    for i:= 0; i < len(pi); i++ {
        copy(permutedDB[i*rowLen:(i+1)*rowLen], flatDB[pi[i]*rowLen:(pi[i]+1)*rowLen])
    }
    
    return permutedDB
}

//hash an already flattened db
func Hash(flatDB []byte) []byte {
    hash := sha256.Sum256(flatDB)
    return hash[:]
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

//check that shares sum to zero
func CheckSharesAreZero(batchSize, numServers int, shares []byte) bool {
    var hopefullyZero, anotherShare modp.Element
    for i:=0; i < batchSize; i++ {
        hopefullyZero.SetBytes(shares[16*i:16*(i+1)])
        for j:=1; j < numServers; j++ {
            index := j*16*batchSize + 16*i
            anotherShare.SetBytes(shares[index:index+16])
            hopefullyZero.Add(&anotherShare, &hopefullyZero)
        }
        if !hopefullyZero.IsZero() {
            log.Println(i)
            return false;
        }
    }
    return true;
}

func TestCheckSharesAreZero() bool {
    batchSize := 5
    numServers := 2
    
    zeroVals := make([]byte, 16*batchSize)
    
    shares := Share(numServers, zeroVals)

    flatShares := make([]byte, 0)
    for i:=0; i < len(shares); i++ {
        flatShares = append(flatShares, shares[i]...)
    }
    
    return CheckSharesAreZero(batchSize, numServers, flatShares)
}

func BeaverProduct(msgBlocks, numServers, batchSize int, beavers, mergedMaskedShares []byte, myExpandedKeyShares, db [][]byte, leader bool) []byte {
    //locally compute product shares and share of mac, subtract from share of given tag
    macDiffShares := make([]byte, 0)
    var maskedKey, myKeyShare, maskedMsg, myMsgShare, givenTag, temp modp.Element
    for i:=0; i < batchSize; i++ {
        var runningSum, beaverProductShare modp.Element
        for j:=0; j < msgBlocks+1; j++ {
            //do a beaver multiplication here
            myKeyShare.SetBytes(myExpandedKeyShares[i][16*j:16*(j+1)])
            myMsgIndex := numServers*16 + 16 + 16*j
            myMsgShare.SetBytes(db[i][myMsgIndex:myMsgIndex+16])
            keyIndex := i*16*(msgBlocks+1) + 16*j
            msgIndex := len(mergedMaskedShares)/2 + keyIndex
            maskedKey.SetBytes(mergedMaskedShares[keyIndex:keyIndex+16])
            maskedMsg.SetBytes(mergedMaskedShares[msgIndex:msgIndex+16])
             
            if leader {
                beaverProductShare.Mul(&maskedKey, &maskedMsg)
            } else {
                beaverProductShare.SetZero()
            }
            maskedKey.Mul(&maskedKey, &myMsgShare) //this now holds a product, not a masked key
            maskedMsg.Mul(&maskedMsg, &myKeyShare) //this now holds a product, not a masked msg
            beaverProductShare.Sub(&maskedKey, &beaverProductShare)
            beaverProductShare.Add(&beaverProductShare, &maskedMsg)
            beaverIndex := 48*(msgBlocks+1)*i + 48*j + 32
            temp.SetBytes(beavers[beaverIndex:beaverIndex+16])
            beaverProductShare.Add(&beaverProductShare, &temp)
            
            runningSum.Add(&runningSum, &beaverProductShare)
        }
        givenTag.SetBytes(db[i][numServers*16:numServers*16 + 16])
        runningSum.Sub(&runningSum, &givenTag)
        macDiffShares = append(macDiffShares, runningSum.Bytes()...)
    }
    return macDiffShares
}

//get all the masked stuff together for the blind mac verification
func GetMaskedStuff(batchSize, msgBlocks, numServers, myNum int, beavers []byte, db [][]byte) ([]byte, [][]byte) {
    maskedExpandedKeyShares := make([]byte, 0)
    maskedMsgShares := make([]byte, 0)
    var value, mask modp.Element
    
    myExpandedKeyShares := make([][]byte, batchSize)
    
    for i:=0; i < batchSize; i++ {
        myExpandedKeyShares[i] = AesPRG((msgBlocks+1)*16, db[i][myNum*16:(myNum+1)*16])
        for j:=0; j < msgBlocks+1; j++ {
            //mask the key component
            value.SetBytes(myExpandedKeyShares[i][16*j:16*(j+1)])
            beaverIndex := 48*(msgBlocks+1)*i + 48*j
            mask.SetBytes(beavers[beaverIndex:beaverIndex+16])
            value.Sub(&value, &mask)
            maskedExpandedKeyShares = append(maskedExpandedKeyShares, value.Bytes()...)
            
            //mask the message component
            msgIndex := numServers*16 + 16 + 16*j
            beaverIndex += 16
            value.SetBytes(db[i][msgIndex:msgIndex+16])
            mask.SetBytes(beavers[beaverIndex:beaverIndex+16])
            value.Sub(&value,&mask)
            maskedMsgShares = append(maskedMsgShares, value.Bytes()...)
        }
    }
    
    maskedStuff := append(maskedExpandedKeyShares, maskedMsgShares...)
    return maskedStuff, myExpandedKeyShares
}



