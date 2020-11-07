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
    
    ct := make([]byte, msgLen)
    c, err := aes.NewCipher(seed)
    if err != nil {
        log.Println("Couldn't inititate new cipher")
        panic(err)
    }

    //our biggest DBs will fortunately have lengths that still fit in ints
    numThreads, chunkSize := PickNumThreads(msgLen)
    empty := make([]byte, chunkSize)
    blocker := make(chan int)
    for i:=0; i < numThreads; i++ {
        startIndex := i*chunkSize;
        endIndex := (i+1)*chunkSize
        go func(start, end int) {
            iv := make([]byte, 16)
            copy(iv[0:4], intToByte(start))
            ctr := cipher.NewCTR(c, iv)
            ctr.XORKeyStream(ct[start:end], empty)
            blocker <- 1
        }(startIndex, endIndex)
    }
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
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
    
    numThreads, chunkSize := PickNumThreads(numBlocks)
    blocker := make(chan int)
    
    //add in the corresponding elements from subsequent shares
    for i:=1; i < numShares; i++ {
        if len(shares[i]) != len(shares[0]) {
            panic("messages being merged have different lengths")
        }
        
        for t := 0; t<numThreads; t++ {
            startIndex := t*chunkSize
            endIndex := (t+1)*chunkSize
            go func(startJ, endJ int) {
                var temp modp.Element
                for j:=startJ; j < endJ; j++ {
                    temp.SetBytes(shares[i][16*j:16*(j+1)])
                    elements[j].Add(elements[j], &temp)
                }
                blocker <- 1
            }(startIndex, endIndex)
        }
        
        for j:=0; j < numThreads; j++ {
            <- blocker
        }
    }
    
    //convert the whole thing to []byte
    output := make([]byte, 0)
    for j:=0; j < numBlocks; j++ {
        output = append(output, elements[j].Bytes()...)
    }
    
    return output
}

func PickNumThreads(size int) (int,int) {
    numThreads := 16
    if size % 16 != 0 {
        //log.Println("using batchSize divisible by 16 will give better performance")
        if size % 8 == 0 {
            numThreads = 8
        } else if size % 4 == 0 {
            numThreads = 4
        } else if size % 2 == 0 {
            numThreads = 2
        } else {
            numThreads = 1
        }
        //log.Printf("using %d threads\n", numThreads)
    }
    //_ = numThreads
    //return 1, size
    return numThreads, size/numThreads
}

func AddOrSub(a, b []byte, add bool) {
    numBlocks := len(a)/16
    
    numThreads,chunkSize := PickNumThreads(numBlocks)
    
    blocker := make(chan int)
    
    for j:=0; j < numThreads; j++ {
        startIndex := j*chunkSize
        endIndex := (j+1)*chunkSize
        go func(startI, endI int) {
            var eltA, eltB modp.Element
            for i :=startI; i < endI; i++ {
                eltA.SetBytes(a[16*i:16*(i+1)])
                eltB.SetBytes(b[16*i:16*(i+1)])
                
                if add {
                    eltA.Add(&eltA, &eltB)
                } else {
                    eltA.Sub(&eltA, &eltB)
                }
                
                copy(a[16*i:16*(i+1)], eltA.Bytes())
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:= 0; i < numThreads; i++ {
        <- blocker
    }
}

//we often do 2 add/subtract ops in a row. This should save some format converting
func DoubleAddOrSub(a, b, c []byte, add1, add2 bool) {
    numBlocks := len(a)/16
    
    numThreads,chunkSize := PickNumThreads(numBlocks)
    
    blocker := make(chan int)
    
    for j:=0; j < numThreads; j++ {
        startIndex := j*chunkSize
        endIndex := (j+1)*chunkSize
        go func(startI, endI int) {
            var eltA, eltB, eltC modp.Element
            for i :=startI; i < endI; i++ {
                eltA.SetBytes(a[16*i:16*(i+1)])
                eltB.SetBytes(b[16*i:16*(i+1)])
                eltC.SetBytes(c[16*i:16*(i+1)])
                
                if add1 {
                    eltA.Add(&eltA, &eltB)
                } else {
                    eltA.Sub(&eltA, &eltB)
                }
                
                if add2 {
                    eltA.Add(&eltA, &eltC)
                } else {
                    eltA.Sub(&eltA, &eltC)
                }
                
                copy(a[16*i:16*(i+1)], eltA.Bytes())
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:= 0; i < numThreads; i++ {
        <- blocker
    }
}

//generate a permutation of the numbers [0, n)
func GenPerm(n int, seed []byte) []int {
    perm := make([]int, n)
    randomness := AesPRG(4*n, seed)
    
    for i:=1; i < n; i++ {
        j := byteToInt(randomness[4*i:4*(i+1)]) % (i+1)
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
func GenBeavers(numBeavers int, seeds [][]byte) [][]byte {
    
    numServers := len(seeds)
    beaversC := make([]byte, numBeavers*16)
    beaversA := make([][]byte, numServers)
    beaversB := make([][]byte, numServers)

    
    numThreads, chunkSize := PickNumThreads(numBeavers)
    blocker := make(chan int)
    
    //expand a and b shares
    for i:=0; i < numServers; i++ {
        go func(index int) {
            beaversA[index] = AesPRG(16*numBeavers, seeds[index][48:64])
            blocker <- 1
        }(i)
        go func(index int) {
            beaversB[index] = AesPRG(16*numBeavers, seeds[index][64:80])
            blocker <- 1
        }(i)
    }
    
    for i:=0; i < 2*numServers; i++ {
        <- blocker
    }
    
    //merge a and b shares
    beaversAMerged := Merge(beaversA)
    beaversBMerged := Merge(beaversB)
    
    //compute c
    for j:=0;j<numThreads; j++ {
        startIndex := j*chunkSize
        endIndex := (j+1)*chunkSize
        go func(startI, endI int) {
            //generate triples a,b,c s.t. a*b=c
            var eltA, eltB, eltC modp.Element
            for i:= startI; i < endI; i++ {
                eltA.SetBytes(beaversAMerged[i*16:(i+1)*16])
                eltB.SetBytes(beaversBMerged[i*16:(i+1)*16])
                eltC.Mul(&eltA, &eltB)
                copy(beaversC[16*i:16*(i+1)], eltC.Bytes())
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    //share the beaver triples
    return Share(numServers, beaversC)
}

func TestGenBeavers() bool {
    numBeavers := 3
    numServers := 2
    
    seeds := make([][]byte, numServers)
    for i:=0; i < numServers; i++ {
        seeds[i] = make([]byte, 96)
        _,err := rand.Read(seeds[i])
        if err != nil {
            panic(err)
        }
    }
    beaversAShares := make([][]byte, numServers)
    beaversBShares := make([][]byte, numServers)
    for i:=0; i < numServers; i++ {
        beaversAShares[i] = AesPRG(48, seeds[i][48:64])
        beaversBShares[i] = AesPRG(48, seeds[i][64:80])
    }
    
    beaversA := Merge(beaversAShares)
    beaversB := Merge(beaversBShares)
    beaversC := Merge(GenBeavers(numBeavers, seeds))
    
    var a, b, c, prod modp.Element
    for i:=0; i < numBeavers; i++ {
        startBeaver := i*16
        a.SetBytes(beaversA[startBeaver:startBeaver+16])
        b.SetBytes(beaversB[startBeaver:startBeaver+16])
        c.SetBytes(beaversC[startBeaver:startBeaver+16])
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
func GenShareTrans(batchSize, blocksPerRow int, seeds [][]byte) []byte {
    
    numServers := len(seeds)
    perms := make([][]int, numServers)
    aInitial := make([][]byte, numServers)
    aAtPermTime := make([][]byte, numServers)
    bFinal := make([][]byte, numServers)

    //length of db
    dbSize := batchSize*blocksPerRow*16
    
    blocker := make(chan int)
    
    //expand all the seeds
    for serverNum := 0; serverNum < numServers; serverNum++ {
        go func(serverNum int) {
            perms[serverNum] = GenPerm(batchSize, seeds[serverNum][80:96])
            blocker <- 1
        }(serverNum)
        go func(serverNum int) {
            if serverNum > 0 {
                aInitial[serverNum] = AesPRG(dbSize, seeds[serverNum][0:16])
            }
            blocker <- 1
        }(serverNum)
        go func(serverNum int) {
            if serverNum != numServers - 1 {
                bFinal[serverNum] = AesPRG(dbSize, seeds[serverNum][16:32])
            }
            blocker <- 1
        }(serverNum)
        go func(serverNum int) {
            if serverNum != numServers - 1 {
                aAtPermTime[serverNum] = AesPRG(dbSize, seeds[serverNum][32:48])
            }
            blocker <- 1
        }(serverNum)
    }
    
    //wait to finish expansion
    for i:=0; i < 4*numServers; i++ {
        <- blocker
    }
    
    aInitSum := make([]byte, dbSize)
    bFinalSum := make([]byte, dbSize)
    
    //get sums for initial and final parts
    for i:=0; i < numServers; i++ {
        if i != 0 {
            AddOrSub(aInitSum, aInitial[i], true)
        }
        
        if i != numServers - 1 {
            AddOrSub(bFinalSum, bFinal[i], true)
        }
    }

    delta := make([]byte, dbSize)
    temp := aInitSum
    //now just need to compute the very last delta
    for i:=0; i < numServers; i++ {
        if i != numServers - 1 {
            temp = PermuteDB(temp, perms[i])
            AddOrSub(temp, aAtPermTime[i], true)
        } else { // i == numServers -1
            temp = PermuteDB(temp, perms[i])
            //here we actually compute the last delta
            DoubleAddOrSub(delta, temp, bFinalSum, false, false)
        }
    }

    return delta
}


/*func TestGenShareTrans() bool {
    
    batchSize := 100
    blocksPerRow := 64
    numServers := 2
    
    //batchSize 10, blocks per row 5, numServers 2
    perms, aInitial, aAtPermTime, bFinal, sAtPermTime, deltas := GenShareTrans(batchSize, blocksPerRow, numServers)
    
    pis := make([][]int, numServers)
    pis[0] = make([]int, 0)
    pis[1] = make([]int, 0)
    for i:=0; i < batchSize; i++ {
        pis[0] = append(pis[0], byteToInt(perms[0][4*i:4*(i+1)]))
        pis[1] = append(pis[1], byteToInt(perms[1][4*i:4*(i+1)]))

    }
    //log.Println(pis[0])
    //log.Println(pis[1])

    flatDB := make([]byte, batchSize*blocksPerRow*16)
    
    //make aInitial values negative
    AddOrSub(flatDB, aInitial[1], false)
    
    flatDB = PermuteDB(flatDB, pis[0])
    
    AddOrSub(flatDB, deltas[0], true)
    
    AddOrSub(flatDB, aAtPermTime[0], false)
    
    //server 1 starts here
    AddOrSub(flatDB, sAtPermTime[1], true)
    
    flatDB = PermuteDB(flatDB, pis[1])
        
    AddOrSub(flatDB, deltas[1], true)
    
    AddOrSub(flatDB, bFinal[0], true)
    
    zero := make([]byte, batchSize*blocksPerRow*16)
    
    return bytes.Equal(flatDB, zero)
}*/


func PermuteDB(flatDB []byte, pi []int) []byte{
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
    
    numThreads, chunkSize := PickNumThreads(len(flatDB))
    subHashes := make([]byte, numThreads*32)
    blocker := make(chan int)
    
    for i:=0; i < numThreads; i++ {
        startIndex := i*chunkSize
        endIndex := (i+1)*chunkSize
        go func(index, start, end int) {
            subHash := sha256.Sum256(flatDB[start:end])
            copy(subHashes[index*32:(index+1)*32], subHash[:])
            blocker <- 1
        }(i, startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    hash := sha256.Sum256(subHashes)
    return hash[:]
}

//check hashes of many flat DBs
func CheckHashes(hashes, dbs []byte, dbLen, myNum int) bool {
    
    resChan := make(chan bool)
    res := true
    
    for i:=0; i < len(hashes)/32; i++ {
        if i == myNum {
            continue
        }
        go func(index int) {
            hash := Hash(dbs[dbLen*index:dbLen*(index+1)])
            if bytes.Equal(hashes[32*index:32*(index+1)], hash[:]) {
                resChan <- true
            } else {
                resChan <- false
            }
        }(i)
    }
    
    for i:=1; i < len(hashes)/32; i++ {
        res = res && <- resChan
    }
    return res
}

//check that shares sum to zero
func CheckSharesAreZero(batchSize, numServers int, shares []byte) bool {
    
    numThreads, chunkSize := PickNumThreads(batchSize)
    res := true;
    resChan := make(chan bool)
    
    for t:=0; t < numThreads; t++ {
        startIndex := t*chunkSize
        endIndex := (t+1)*chunkSize
        go func(startI, endI int) {
            var hopefullyZero, anotherShare modp.Element
            innerRes := true
            for i:=startI; i < endI; i++ {
                hopefullyZero.SetBytes(shares[16*i:16*(i+1)])
                for j:=1; j < numServers; j++ {
                    index := j*16*batchSize + 16*i
                    anotherShare.SetBytes(shares[index:index+16])
                    hopefullyZero.Add(&anotherShare, &hopefullyZero)
                }
                if !hopefullyZero.IsZero() {
                    innerRes = false
                }
            }
            resChan <- innerRes
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        res = res && <- resChan
    }
    
    return res;
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

func BeaverProduct(msgBlocks, numServers, batchSize int, beaversC, mergedMaskedShares []byte, myExpandedKeyShares, db [][]byte, leader bool) []byte {
    //locally compute product shares and share of mac, subtract from share of given tag
    macDiffShares := make([]byte, 16*batchSize)
    blocker := make(chan int)
    numThreads, chunkSize := PickNumThreads(batchSize)
    
    for t:=0; t < numThreads; t++ {
        startIndex := t*chunkSize
        endIndex := (t+1)*chunkSize
        go func(start, end int) {
            for i:=start; i < end; i++ {
                var maskedKey, myKeyShare, maskedMsg, myMsgShare, givenTag, temp modp.Element
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
                    beaverIndex := 16*(msgBlocks+1)*i + 16*j
                    temp.SetBytes(beaversC[beaverIndex:beaverIndex+16])
                    beaverProductShare.Add(&beaverProductShare, &temp)
                    
                    runningSum.Add(&runningSum, &beaverProductShare)
                }
                givenTag.SetBytes(db[i][numServers*16:numServers*16 + 16])
                runningSum.Sub(&runningSum, &givenTag)
                        
                copy(macDiffShares[16*i:16*(i+1)], runningSum.Bytes())
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    return macDiffShares
}

//get all the masked stuff together for the blind mac verification
func GetMaskedStuff(batchSize, msgBlocks, numServers, myNum int, beaversA, beaversB []byte, db [][]byte) ([]byte, [][]byte) {
    maskedExpandedKeyShares := make([]byte, 16*batchSize*(msgBlocks+1))
    maskedMsgShares := make([]byte, 16*batchSize*(msgBlocks+1))
    
    myExpandedKeyShares := make([][]byte, batchSize)
    
    numThreads, chunkSize := PickNumThreads(batchSize)
    blocker := make(chan int)
    
    for t:= 0; t < numThreads; t++ {
        startIndex := chunkSize*t
        endIndex := chunkSize*(t+1)
        go func(startI, endI int) {
            var value, mask modp.Element
            for i:=startI; i < endI; i++ {
                myExpandedKeyShares[i] = AesPRG((msgBlocks+1)*16, db[i][myNum*16:(myNum+1)*16])
                for j:=0; j < msgBlocks+1; j++ {
                    //mask the key component
                    value.SetBytes(myExpandedKeyShares[i][16*j:16*(j+1)])
                    beaverIndex := 16*(msgBlocks+1)*i + 16*j
                    mask.SetBytes(beaversA[beaverIndex:beaverIndex+16])
                    value.Sub(&value, &mask)
                    index := 16*(msgBlocks+1)*i + 16*j
                    copy(maskedExpandedKeyShares[index:index+16], value.Bytes())
                    
                    //mask the message component
                    msgIndex := numServers*16 + 16 + 16*j
                    value.SetBytes(db[i][msgIndex:msgIndex+16])
                    mask.SetBytes(beaversB[beaverIndex:beaverIndex+16])
                    value.Sub(&value,&mask)
                    copy(maskedMsgShares[index:index+16], value.Bytes())
                }
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    maskedStuff := append(maskedExpandedKeyShares, maskedMsgShares...)
    return maskedStuff, myExpandedKeyShares
}



