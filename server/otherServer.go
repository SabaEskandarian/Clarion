package main

import (
    "log"
    "crypto/tls"
    //"net"
    //"os"
    //"time"
    //"unsafe"
    //"io"
    //"crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/sign"
    //"sync/atomic"
    "strings"
    "strconv"

    "shufflemessage/mycrypto" 
)

func server(numServers, msgBlocks, batchSize, myNum int, leaderAddr string) {
    
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    pubKeys := make([]*[32]byte, numServers)
    verKeys := make([]*[32]byte, numServers)
    
    var err error
    var mySecKey *[32]byte
    var auxSharedKey [32]byte
    var mySignKey *[64]byte

    auxPubKey, _, err := box.GenerateKey(strings.NewReader(strings.Repeat("a", 10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    for i := 0; i < numServers; i++ {
        
        if i == myNum {
            pubKeys[i], mySecKey, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
            
            verKeys[i], mySignKey, err = sign.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        } else {
            pubKeys[i], _, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
            
            verKeys[i], _, err = sign.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        }
    }
    
    box.Precompute(&auxSharedKey, auxPubKey, mySecKey)
 
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to server
    conn, err := tls.Dial("tcp", leaderAddr, conf)
    if err != nil {
        log.Println(err)
        return 
    }
    defer conn.Close()
    
    //some relevant values
    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    //server share is longer because there needs to be space for a share of _each_ mac key share
    serverShareLength := 16*msgBlocks + 32 + numServers * 16
    blocksPerRow :=  msgBlocks + numServers + 2 //2 is for the mac and enc key, numServers for the mac key shares
    numBeavers := batchSize * (msgBlocks + 1) // +1 is for the encryption key which is included in the mac
    dbSize := blocksPerRow*batchSize*16
    //bigbox has nonce, beavers, perm, delta, abs, and box encryption overhead
    bigBoxSize := 24 + numBeavers*48 + 4*batchSize + dbSize + 2*(numServers-1)*dbSize + box.Overhead
    
    //data structure for holding batch of messages
    //each entry will be of length serverShareLength
    db := make([][]byte, batchSize)
    for i:= 0; i < batchSize; i++ {
        db[i] = make([]byte, serverShareLength)
    }

    var nonce [24]byte

    //main server loop below
    for {
        //client connection receiving phase
        for msgCount := 0; msgCount < batchSize; msgCount++ {
            
            //read permuted index from leader
            prelimPermIndex := byteToInt(readFromConn(conn, 4))
            
            //read client box from leader, unbox
            clientBox := readFromConn(conn, boxedShareLength)
            
            clientMessage, ok := box.OpenAnonymous(nil, clientBox, pubKeys[myNum], mySecKey)
            if !ok {
                panic("decryption not ok!!")
            }
            
            //expand seeds, store in db
            copy(db[prelimPermIndex][0:16*numServers], 
                mycrypto.ExpandKeyShares(myNum, numServers, clientMessage[0:16]))
            copy(db[prelimPermIndex][16*numServers:], clientMessage[16:shareLength])

        }
        
        //processing phase

        //unbox and read the beaver triples/share translation info
        messageBox := readFromConn(conn, bigBoxSize)
        
        copy(nonce[:], messageBox[:24])
        
        contents,ok := box.OpenAfterPrecomputation(nil, messageBox[24:], &nonce, &auxSharedKey)
        if !ok {
            panic("error in decryption")
        }
                
        beavers := contents[:numBeavers*48]
        piBytes := contents[numBeavers*48:numBeavers*48+batchSize*4]
        pi := make([]int, 0)
        for i:=0; i < batchSize; i++ {
            pi = append(pi, byteToInt(piBytes[4*i:4*(i+1)]))
        }
        delta := contents[numBeavers*48+batchSize*4:numBeavers*48+batchSize*4+dbSize]
        abs := make([][]byte, numServers)
        startIndex := numBeavers*48+batchSize*4+dbSize
        for i:=0; i < numServers; i++ {
            if i != myNum {
                abs[i] = contents[startIndex:startIndex+2*dbSize]
                startIndex+=2*dbSize
            }
        }
        
        //blind MAC verification, 
        //there is unfortunately a lot of duplication between the code here and the code in the leader
        
        //expand the key shares into the individual mac key shares, mask them and the msg shares with part of a beaver triple
        maskedStuff, myExpandedKeyShares := mycrypto.GetMaskedStuff(batchSize, msgBlocks, numServers, myNum, beavers, db)
        
        //send maskedStuff to leader
        writeToConn(conn, maskedStuff)
        
        //receive mergedMaskedShares
        mergedMaskedShares := readFromConn(conn, len(maskedStuff))
        
        //locally compute product shares and share of mac, subtract from share of given tag
        macDiffShares := mycrypto.BeaverProduct(msgBlocks, numServers, batchSize, beavers, mergedMaskedShares, myExpandedKeyShares, db, false)
        
        //sign macDiffShares, send to leader, receive signed shares from leader
        mySignedMacDiffShares := sign.Sign(nil, macDiffShares, mySignKey)
        writeToConn(conn, mySignedMacDiffShares)
        macDiffLength := 16*batchSize
        objectSize := sign.Overhead + macDiffLength
        allSignedMacDiffShares := readFromConn(conn, numServers*objectSize)
        
        //verify signatures
        finalMacDiffShares := make([]byte, 0)
        for i:=0; i < numServers; i++ {
            object,ok := sign.Open(nil, allSignedMacDiffShares[i*objectSize:(i+1)*objectSize], verKeys[i])
            if !ok {
                panic("signature didn't verify")
            }
            finalMacDiffShares = append(finalMacDiffShares, object...)
        }
        
        //verify the macs come out to 0
        success := mycrypto.CheckSharesAreZero(batchSize, numServers, finalMacDiffShares)
        if !success {
            panic("blind mac verification failed")
        }
        
        //TODO: shuffle
        
        //commit, reveal, mac verify, decrypt
        
        //hash the whole DB
        flatDB, hash := mycrypto.FlattenAndHash(db)
        signedHash := sign.Sign(nil, hash, mySignKey)
        
        //send signed hashed DB to leader
        writeToConn(conn, signedHash)
        //receive all signedhashed DBs from leader
        signedHashes := readFromConn(conn, numServers*(32+sign.Overhead))
        
        //check all the signatures on hashes
        hashes := make([]byte, 0)
        objectSize = 32 + sign.Overhead
        for i:=0; i < numServers; i++ {
            hash,ok := sign.Open(nil, signedHashes[i*objectSize:(i+1)*objectSize], verKeys[i])
            if !ok {
                panic("signature didn't verify")
            }
            hashes = append(hashes, hash...)
        }
        
        //send real DB to leader
        writeToConn(conn, flatDB)
        //receive all the real DBs from leader
        flatDBs := readFromConn(conn, numServers*dbSize)
        //check that the received DBs match the received hashes
        if !mycrypto.CheckHashes(hashes, flatDBs, dbSize) {
            panic("hashes did not match")
        }
        //merge DBs
        mergedDB := mergeFlattenedDBs(flatDBs, numServers, len(flatDB))
        //check macs in merged DBs and decrypt
        outputDB, ok := checkMacsAndDecrypt(mergedDB, numServers, msgBlocks, batchSize)
        if !ok {
            panic("macs did not verify")
        }
        
        _, _, _ = beavers, delta, outputDB //TODO beavers and delta will be used
        
    }
}
