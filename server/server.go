package main

import (
    "log"
    "crypto/tls"
    "net"
    "os"
    "time"
    //"unsafe"
    //"crypto/rand"
    "golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
    "bufio"
    "strings"
    
    "shufflemessage/mycrypto" 
)

func main() {
    
    numServers := 0
    msgBlocks := 0
    batchSize := 0    
    serverNum := 0
    paramFile := ""
    paramNum := 0
    
    log.SetFlags(log.Lshortfile)
        
    if len(os.Args) < 4 {
        log.Println("usage: server [servernum] [paramFile] [paramChoice]")
        log.Println("servers 0... are the shuffling servers. Start them in order.")
        log.Println("server -1 is the aux server. Start it last. ")
        log.Println("paramFile format is all the server addresses (addr:port), each value on a separate line. Then there's any number of sets of 4 lines holding 'PARAMS', numServers, blocks per msg, and batch size. [paramChoice] is a number i that picks the ith set of parameters to run the system with (i starting at 1). ")
        return
    } else {
        serverNum, _ = strconv.Atoi(os.Args[1])
        paramFile = os.Args[2]
        paramNum,_ = strconv.Atoi(os.Args[3])
    }
    
    if paramNum == 0 {
        log.Println("paramChoice starts at 1")
        return
    }
    
    file, err := os.Open(paramFile)
    if err != nil {
        panic(err)
    }
    
    addrs := make([]string, 0)
    ports := make([]string, 0)
    scanner := bufio.NewScanner(file)
    scanner.Scan()
    for i:= 0; scanner.Text() != "PARAMS"; i++ {
        addrs = append(addrs, scanner.Text())
        //get the port number out
        colonPos := strings.Index(addrs[i], ":")
        if colonPos == -1 {
            panic("server addresses must include :port")
        }
        ports = append(ports, addrs[i][colonPos:])
        scanner.Scan()
    }
    
    paramCount := 1
    
    for paramCount < paramNum {
        scanner.Scan()
        scanner.Scan()
        scanner.Scan()
        scanner.Scan()
        paramCount++
    }
    
    scanner.Scan()
    numServers, _ = strconv.Atoi(scanner.Text())
    scanner.Scan()
    msgBlocks, _ = strconv.Atoi(scanner.Text())
    scanner.Scan()
    batchSize, _ = strconv.Atoi(scanner.Text())
    
    if numServers == 0 {
        log.Println("numServers is 0. Perhaps there is a params error?")
        return
    }
    
    
    log.Printf("numServers %d\n", numServers)
    log.Printf("msgBlocks %d\n", msgBlocks)
    log.Printf("batchSize %d\n", batchSize)

    err = scanner.Err()
    if err != nil {
        panic(err)
    }
    file.Close()
    
    leader := false
    myNum := serverNum
    
    if serverNum == -1 { //aux server
        aux(numServers, msgBlocks, batchSize, addrs)
        return
    } else if serverNum == 0 {
        log.Println("This server is the leader")
        leader = true
    } else {
        log.Printf("This is server %d\n", serverNum)
    }
    
    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen("tcp", ports[serverNum], config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()
    
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //set up connections between all the servers
    //holds connections to the other shuffle servers
    //conns[serverNum] will be empty
    conns := make([]net.Conn, numServers)
    
    //each server connects to the ones with lower indices
    //except at the end aux connects to all of them
    //connect to lower numbered servers
    for i:=0; i < serverNum; i++ {
        conns[i], err = tls.Dial("tcp", addrs[i], conf)
        if err != nil {
            log.Println(err)
            return 
        }
        defer conns[i].Close()
        readFromConn(conns[i], 4)
    }
    
    log.Println("connected to lower numbered servers")
    
    //wait for connections from higher numbered servers
    for i:= serverNum+1; i < numServers; i++ {
        conns[i], err = ln.Accept()
        if err != nil {
            log.Println(err)
            return
        }
        conns[i].SetDeadline(time.Time{})
        writeToConn(conns[i], intToByte(1))
    }
    
    log.Println("connected to higher numbered servers")
    
    //connection from aux server
    auxConn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        return
    }
    auxConn.SetDeadline(time.Time{})
    writeToConn(auxConn, intToByte(1))
    
    log.Println("connected to aux server")
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    pubKeys := make([]*[32]byte, numServers)
    var mySecKey *[32]byte
    
    for i := 0; i < numServers; i++ {
        if i == serverNum {
            pubKeys[i], mySecKey, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
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
        }
    }
    
    //some relevant values
    //server share is longer because there needs to be space for a share of _each_ mac key share
    serverShareLength := 16*msgBlocks + 32 + numServers * 16
    blocksPerRow :=  msgBlocks + numServers + 2 //2 is for the mac and enc key, numServers for the mac key shares
    numBeavers := batchSize * (msgBlocks + 1) // +1 is for the encryption key which is included in the mac
    dbSize := blocksPerRow*batchSize*16
    
    //data structure for holding batch of messages
    //each entry will be of length serverShareLength
    db := make([][]byte, batchSize)
    for i:= 0; i < batchSize; i++ {
        db[i] = make([]byte, serverShareLength)
    }
    flatDB := make([]byte, dbSize)

    //set up running average for timing
    batchesCompleted := 0
    var totalTime, totalBlindMacTime, totalShuffleTime, totalRevealTime time.Duration
    
    numThreads, _ := mycrypto.PickNumThreads(batchSize)

    log.Printf("using %d threads", numThreads)
    if numThreads != 16 {
        log.Println("performance could be improved by using a batchSize divisible by 16")
    }
    
    for {
        
        log.Println("server ready")
        //receiving client connections phase 
        if leader {
            leaderReceivingPhase(db, conns, msgBlocks, batchSize, ln)
        } else {
            otherReceivingPhase(db, conns[0], numServers, msgBlocks, batchSize, pubKeys[serverNum], mySecKey, serverNum)
        }
        
        //processing phase
        //NOTE: in reality, the blind verification and aux server stuff could be done as messages arrive
        //this would speed up the processing time, esp. if the server were multithreaded
        //but I'm handling everything for a batch at once so I can report performance for processing a batch
        startTime := time.Now()

        if leader {
            //ping aux server
            emptyByte := make([]byte, 4)
            writeToConn(auxConn, emptyByte)
        }
        
        //read beaver triples and share translation stuff
        beavers := readFromConn(auxConn, numBeavers*48)
        piBytes := readFromConn(auxConn, batchSize*4)
        pi := make([]int, 0)
        for i:=0; i < batchSize; i++ {
            pi = append(pi, byteToInt(piBytes[4*i:4*(i+1)]))
        }
        delta := readFromConn(auxConn, dbSize)
        
        aInitial := make([]byte, 0)
        sAtPermTime := make([]byte, 0)
        bFinal := make([]byte, 0)
        aAtPermTime := make([]byte, 0)
        
        if serverNum != 0 {
            aInitial = readFromConn(auxConn, dbSize)
            sAtPermTime = readFromConn(auxConn, dbSize)
        }
        
        if serverNum != numServers - 1 {
            bFinal = readFromConn(auxConn, dbSize)
            aAtPermTime = readFromConn(auxConn, dbSize)
        }
        
        //if numServers > 2, timing starts here. If numServers == 2, timing starts with processing phase
        if numServers > 2 {
            startTime = time.Now()

            //NOTE: time might appear worse than it really is since I'm not waiting on everyone receiving the preprocessing info before starting this stage, but I don't think it matters too much. I can change that if it does
        }

        blindMacStartTime := time.Now()
        
        //blind mac verification
        
        //expand the key shares into the individual mac key shares, mask them and the msg shares with part of a beaver triple
        maskedStuff, myExpandedKeyShares := mycrypto.GetMaskedStuff(batchSize, msgBlocks, numServers, myNum, beavers, db)
        
        //everyone distributes shares and then merges them
        broadcast(maskedStuff, conns, serverNum)
        maskedShares := receiveFromAll(maskedStuff, conns, serverNum)
                
        mergedMaskedShares := mergeFlattenedDBs(maskedShares, numServers, len(maskedStuff))
                
        //everyone distributes (computed mac - provided tag) shares
        macDiffShares := mycrypto.BeaverProduct(msgBlocks, numServers, batchSize, beavers, mergedMaskedShares, myExpandedKeyShares, db, leader)
        
        //broadcast shares and verify everything sums to 0
        broadcast(macDiffShares, conns, serverNum)
        finalMacDiffShares := receiveFromAll(macDiffShares, conns, serverNum)
        
        //verify the macs come out to 0
        success := mycrypto.CheckSharesAreZero(batchSize, numServers, finalMacDiffShares)
        if !success {
            panic("blind mac verification failed")
        }
        
        
        blindMacElapsedTime := time.Since(blindMacStartTime)
        shuffleStartTime := time.Now()
        
            
        //shuffle        
        flatten(db, flatDB)
        if serverNum != 0 { //everyone masks their DB share and sends it to server 0

            mycrypto.AddOrSub(flatDB, aInitial, false)//false is for subtraction
            writeToConn(conns[0], flatDB)
        } else { //server 0 does the shuffle
            
            //receive all the values masked with aInitial
            for i:=1; i < numServers; i++ {
                mycrypto.AddOrSub(flatDB, readFromConn(conns[i], dbSize), true)
            }
            
            //permute and apply delta, mask result and send to server 1
            flatDB = mycrypto.PermuteDB(flatDB, pi)
            mycrypto.DoubleAddOrSub(flatDB, delta, aAtPermTime, true, false)
            writeToConn(conns[1], flatDB)
        }
        //the middle servers take turns shuffling
        if serverNum != 0 && serverNum != numServers - 1 {
            //complete the vector to be permuted (read from prev server)             
            mycrypto.AddOrSub(sAtPermTime, readFromConn(conns[serverNum-1], dbSize), true)
            
            //permute and apply delta, mask and send to next server
            flatDB = mycrypto.PermuteDB(sAtPermTime, pi)
            mycrypto.DoubleAddOrSub(flatDB, delta, aAtPermTime, true, false)
            writeToConn(conns[serverNum+1], flatDB)
        }
        //the last server shuffles
        if serverNum == numServers - 1 {
            //complete the vector to be permuted (read from prev server) 
            mycrypto.AddOrSub(sAtPermTime, readFromConn(conns[serverNum-1], dbSize), true)
            
            //permute and apply delta
            flatDB = mycrypto.PermuteDB(sAtPermTime, pi)
            mycrypto.AddOrSub(flatDB, delta, true)
        }
        //bFinal is actually the db here for everyone except the final server
        if serverNum != numServers - 1 {
            flatDB = bFinal
        }
        
        shuffleElapsedTime := time.Since(shuffleStartTime)
        revealTimeStart := time.Now()
        
        
        //commit, reveal, mac verify, decrypt
        
        //hash the whole db
        hash := mycrypto.Hash(flatDB)
        
        //send out hash (commitments)
        broadcast(hash, conns, serverNum)
        hashes := receiveFromAll(hash, conns, serverNum)
        
        //send out full DB after getting everyone's commitment
        broadcast(flatDB, conns, serverNum)
        flatDBs := receiveFromAll(flatDB, conns, serverNum)

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
        
        _ = outputDB 
        
        revealElapsedTime := time.Since(revealTimeStart)
        elapsedTime := time.Since(startTime)
        
        //only the leader outputs the stats
        if leader {

            //log.Println(outputDB);
            
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
}
