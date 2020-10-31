package main

import (
    "log"
    "crypto/tls"
    "net"
    //"os"
    "time"
    //"unsafe"
    //"io"
    //"crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/crypto/nacl/sign"
    //"sync/atomic"
    "strconv"
    "strings"
    
    "shufflemessage/mycrypto" 
)

func leader(numServers, msgBlocks, batchSize int) {
    
    log.Println("This server is the leader")
    
    
    //if !mycrypto.TestCheckSharesAreZero() {
    //    panic("test of checking a share is zero failed")
    //}
    
    //if !mycrypto.TestGenBeavers() {
    //    panic("test of beaver triple generation failed")
    //}
    
    
    //setup
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    verKeys := make([]*[32]byte, numServers)
    
    var err error
    var mySignKey *[64]byte
    
    for i := 0; i < numServers; i++ {
        
        if i == 0 {
            
            verKeys[i], mySignKey, err = sign.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        } else {
            verKeys[i], _, err = sign.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        }
    }
    
    
    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    port := ":4443"
    ln, err := tls.Listen("tcp", port, config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()
    
    //first connection from Aux server
    auxConn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        return
    }
    auxConn.SetDeadline(time.Time{})
        
    //holds connections to the other shuffle servers
    conns := make([]net.Conn, (numServers))

    //we'll just leave the zeroth entry empty
    // so conns[i] is the connection to server i
    for i := 1; i < numServers; i++ {
        conns[i], err = ln.Accept()
        if err != nil {
            log.Println(err)
            return
        }
        conns[i].SetDeadline(time.Time{})
    }
        
    //some relevant values
    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    clientTransmissionLength := (numServers - 1) * boxedShareLength + shareLength
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

    //set up running average for timing
    batchesCompleted := 0
    var totalTime, totalBlindMacTime, totalShuffleTime, totalRevealTime time.Duration
    
    log.Println("server ready")
    //main server behavior below
    for {
        //client connection receiving phase
        //NOTE: this phase of server is currently single-threaded. 
        //Throughput could be significantly increased by making the servers handle multiple client requests concurrently
        
        //generate preliminary permutation
        prelimPerm := mycrypto.GenPerm(batchSize)
        
        //NOTE: the preliminary permutation is effectively "for free" to evaluate because the server just copies the client messages into their permuted indices directly
        
        //for performance measurement we'll only implement the case where all client messages are good
        //we'll just panic later if a blind mac verification fails
        for msgCount := 0; msgCount < batchSize; msgCount++ {
            //handle connections from client, pass on boxes
            
            //client connection
            clientConn, err := ln.Accept()
            if err != nil {
                log.Println(err)
                return
            }
            clientConn.SetDeadline(time.Time{})
            clientTransmission := readFromConn(clientConn, clientTransmissionLength)
            clientConn.Close()
            
            //NOTE: the next steps of handling messages sent to this server and forwarding messages to other servers could definitely be done in parallel too
            
            //handle the message sent for this server
            copy(db[prelimPerm[msgCount]][0:16*numServers], 
                mycrypto.ExpandKeyShares(0, numServers, clientTransmission[0:16]))
            copy(db[prelimPerm[msgCount]][16*numServers:], clientTransmission[16:shareLength])
            
            //pass on the boxes to the other servers, send the index they should be placed in too
            for i := 1; i < numServers; i++ {
                
                //send prelimPerm[msgCount]
                writeToConn(conns[i], intToByte(prelimPerm[msgCount]))
                
                //send client message
                start := shareLength + (i-1)*boxedShareLength
                end := shareLength + i*boxedShareLength
                writeToConn(conns[i], clientTransmission[start:end])
            }
        }
        
        //processing phase
        //NOTE: in reality, the blind verification and aux server stuff could be done as messages arrive
        //this would speed up the processing time, esp. if the server were multithreaded
        //but I'm handling everything for a batch at once so I can report performance for processing a batch
        
        startTime := time.Now()
        
        //ping aux server
        emptyByte := make([]byte, 4)
        writeToConn(auxConn, emptyByte)
        
        //read beaver triples and share translation stuff
        beavers := readFromConn(auxConn, numBeavers*48)
        piBytes := readFromConn(auxConn, batchSize*4)
        pi := make([]int, 0)
        for i:=0; i < batchSize; i++ {
            pi = append(pi, byteToInt(piBytes[4*i:4*(i+1)]))
        }
        delta := readFromConn(auxConn, dbSize)
        abs := make([][]byte, numServers)
        for i:=1; i < numServers; i++ {
            abs[i] = readFromConn(auxConn, 2*dbSize)
        }
        
        //read boxes for other servers and pass them on
        for i:=1; i < numServers; i++ {
            go func(auxConn, conn net.Conn, bigBoxSize int) {
                box := readFromConn(auxConn, bigBoxSize)
                writeToConn(conn, box)
            }(auxConn, conns[i], bigBoxSize)
        }
        
        //if numServers > 2, timing starts here. If numServers == 2, timing starts with processing phase
        if numServers > 2 {
            startTime = time.Now()

            //NOTE: time might appear worse than it really is since I'm not waiting on finishing sending the preprocessing info before starting this stage, but I don't think it matters too much. I can change that if it does
        }
                
        blindMacStartTime := time.Now()
        
        //blind MAC verification
                
        //expand the key shares into the individual mac key shares, mask them and the msg shares with part of a beaver triple
        maskedStuff, myExpandedKeyShares := mycrypto.GetMaskedStuff(batchSize, msgBlocks, numServers, 0, beavers, db)
        
        //receive shares from everyone, merge and broadcast to everyone
        maskedShares := receiveAndSend(maskedStuff, conns, 0)
                
        mergedMaskedShares := mergeFlattenedDBs(maskedShares, numServers, len(maskedStuff))
        
        broadcast(mergedMaskedShares, conns)
        
        macDiffShares := mycrypto.BeaverProduct(msgBlocks, numServers, batchSize, beavers, mergedMaskedShares, myExpandedKeyShares, db, true)
        
        //receive MAC shares from everyone, broadcast them, and verify everything sums to 0
        /*
         * We make sure the MAC shares here are signed so a malicious leader can't
         * convince the others that a msg is valid and then have it be invalid 
         * later when the blocks are revealed. 
         * 
         * I didn't sign the previous messages because I think if the leader tampers with them
         * it could cause a message to be rejected, but that's ok. The only thing we need to 
         * block here is a leader who forces a bad mac to be accepted. 
         * 
         */
        
        //sign macDiffShares, receive and broadcast
        mySignedMacDiffShares := sign.Sign(nil, macDiffShares, mySignKey)
        allSignedMacDiffShares := receiveAndSend(mySignedMacDiffShares, conns, -1)
        
        //verify signatures
        macDiffLength := 16*batchSize
        objectSize := sign.Overhead + macDiffLength
        for i:=1; i < numServers; i++ {
            object,ok := sign.Open(nil, allSignedMacDiffShares[i*objectSize:(i+1)*objectSize], verKeys[i])
            if !ok {
                panic("signature didn't verify")
            }
            macDiffShares = append(macDiffShares, object...)
        }
        
        //verify the macs come out to 0
        success := mycrypto.CheckSharesAreZero(batchSize, numServers, macDiffShares)
        if !success {
            panic("blind mac verification failed")
        }
        
        blindMacElapsedTime := time.Since(blindMacStartTime)
        shuffleStartTime := time.Now()
        
        //TODO: shuffle
        //it would be cool if I can write this in a way that applies to both 2 parties and k parties
        
        shuffleElapsedTime := time.Since(shuffleStartTime)
        revealTimeStart := time.Now()
        
        //commit, reveal, mac verify, decrypt
        
        
        //hash the whole db
        flatDB, hash := mycrypto.FlattenAndHash(db)
        
        signedHash := sign.Sign(nil, hash, mySignKey)
        //receive the signed hashed DBs from everyone and forward them to everyone
        signedHashes := receiveAndSend(signedHash, conns, -1)
        
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
        
        //receive the real DBs from everyone and forward them to everyone
        flatDBs := receiveAndSend(flatDB, conns, -1)
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
        
        revealElapsedTime := time.Since(revealTimeStart)
        
        elapsedTime := time.Since(startTime)
        
        
        log.Println(outputDB);
        
        batchesCompleted++
        totalTime += elapsedTime
        totalBlindMacTime += blindMacElapsedTime
        totalShuffleTime += shuffleElapsedTime
        totalRevealTime += revealElapsedTime
        log.Printf("%d servers, %d msgs per batch, %d byte messages\n", numServers, batchSize, msgBlocks*16)
        log.Printf("blind mac time: %s, average: %s", blindMacElapsedTime, totalBlindMacTime/time.Duration(batchesCompleted))
        log.Printf("shuffle time: %s, average: %s", shuffleElapsedTime, totalShuffleTime/time.Duration(batchesCompleted))
        log.Printf("reveal time: %s, average: %s", revealElapsedTime, totalRevealTime/time.Duration(batchesCompleted))
        log.Printf("batches completed: %d\n", batchesCompleted)
        log.Printf("Time for this batch: %s\n", elapsedTime)
        log.Printf("Average time per batch: %s\n\n\n", totalTime/time.Duration(batchesCompleted))
    }
}


//receive something from everyone and then broadcast everything to:
//everyone if recipient = -1
//nobody if recipient = 0
//a particular person if recipient = i > 0
//returns the broadcasted value for the lead server to use
func receiveAndSend(myContribution []byte, conns []net.Conn, recipient int) []byte {
    blocker := make(chan int)
    numServers := len(conns)
    contentLenPerServer := len(myContribution)
    content := make([]byte, contentLenPerServer*numServers)
    
    copy(content[:contentLenPerServer], myContribution[:])
    
    if recipient < -1 || recipient >= len(conns) {
        panic("incorrect recipient")
    }
        
    //receive from everyone
    for i := 1; i < numServers; i++ {
        go func(outputLocation []byte, conn net.Conn, bytesToRead int) {
            copy(outputLocation, readFromConn(conn, bytesToRead))
            blocker <- 1
            return
        }(content[i*contentLenPerServer:(i+1)*contentLenPerServer], conns[i], contentLenPerServer)
    }
    
    for i := 1; i < numServers; i++ {
        <- blocker
    }
    
    if recipient == -1 {
       broadcast(content, conns)
    } else if recipient > 0 {
        //send just to recipient
        writeToConn(conns[recipient], content)
    }
    
    return content
}

//broadcast a message to everyone
func broadcast(msg []byte, conns []net.Conn) {
    blocker := make(chan int)
    numServers := len(conns)
    
    //broadcast
    for i := 1; i < numServers; i++ {
        go func(data []byte, conn net.Conn) {
            writeToConn(conn, data)
            blocker <- 1
            return
        }(msg, conns[i])
    }
    
    for i := 1; i < numServers; i++ {
        <- blocker
    }
}
