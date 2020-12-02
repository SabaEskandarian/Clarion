package main

import (
    "log"
    "crypto/tls"
    "net"
    "os"
    "time"
    //"unsafe"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
    "bufio"
    "strings"
    "runtime"
    "fmt"
        
    "shufflemessage/mycrypto" 
)

func main() {    
    //for i:=0; i < 10; i++ {
    //    log.Println(mycrypto.TestGenShareTrans())
    //}
    //return
    
    //log.Println(mycrypto.TestGenBeavers())
    //return
    
    numServers := 0
    msgBlocksParams := make([]int, 0)
    batchSizeParams := make([]int, 0)    
    serverNum := 0
    paramFile := ""
    numParams := 0
    messagingModeParams := make([]bool, 0)
    
    
    log.SetFlags(log.Lshortfile)
        
    if len(os.Args) < 3 {
        log.Println("usage: server [servernum] [paramFile]")
        log.Println("servers 0... are the shuffling servers. Start them in order.")
        log.Println("server -1 is the aux server. Start it last. ")
        log.Println("paramFile has one parameter per line. First, the number of servers. Then the number of different parameter sets to evaluate. Then all the server addresses(addr:port). Extra addresses beyond the number of servers are ignored. Then there's a line that says 'PARAMS'. Then sets of three lines indicating whether to run in messaging or standard mode, blocks per msg, and batch size. Examples should be included with the code. ")
        return
    } else {
        serverNum, _ = strconv.Atoi(os.Args[1])
        paramFile = os.Args[2]
    }
    
    file, err := os.Open(paramFile)
    if err != nil {
        panic(err)
    }
    
    addrs := make([]string, 0)
    ports := make([]string, 0)
    scanner := bufio.NewScanner(file)
    scanner.Scan()
    numServers, _ = strconv.Atoi(scanner.Text())
    scanner.Scan()
    numParams, _ = strconv.Atoi(scanner.Text())
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
    
    for i:= 0; i < numParams; i++ {
        scanner.Scan()
        if scanner.Text() == "messaging" {
            messagingModeParams = append(messagingModeParams, true)
        } else {
            messagingModeParams = append(messagingModeParams, false)
        }
        scanner.Scan()
        msgBlocksInput, _ := strconv.Atoi(scanner.Text())
        msgBlocksParams = append(msgBlocksParams, msgBlocksInput)
        scanner.Scan()
        batchSizeInput, _ := strconv.Atoi(scanner.Text())
        batchSizeParams = append(batchSizeParams, batchSizeInput)
    }
    
    err = scanner.Err()
    if err != nil {
        panic(err)
    }
    file.Close()
    
    leader := false
    myNum := serverNum
    
    if serverNum == -1 { //aux server
        aux(numServers, msgBlocksParams, batchSizeParams, addrs, messagingModeParams)
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
        writeToConn(conns[i], intToByte(1))
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
        readFromConn(conns[i], 4)
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
    readFromConn(auxConn, 4)
    
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
    
    for evalNum := 0; evalNum < numParams; evalNum++ {
        messagingMode := messagingModeParams[evalNum]
        msgBlocks := msgBlocksParams[evalNum]
        batchSize := batchSizeParams[evalNum]
        
        log.Printf("numServers %d\n", numServers)
        log.Printf("msgBlocks %d\n", msgBlocks)
        log.Printf("batchSize %d\n", batchSize)
        
        if messagingMode {
            log.Println("in messaging mode; only first block is MACed/verified")
        }
        
        log.Println("\nClient performance test")
        var totalClientTime time.Duration
        for i:= 0; i < 10; i++ {
            _, clientTime:= clientSim(batchSize, msgBlocks, pubKeys, messagingMode)
            totalClientTime += clientTime
            
        }
        fmt.Printf("Client average compute time: %s\n\n", totalClientTime/time.Duration(10))
        
        //some relevant values
        blocksPerRow :=  2*(msgBlocks+1) + 1 
        numBeavers := batchSize * (msgBlocks +1)
        
        if messagingMode {
            blocksPerRow = msgBlocks + 3
            numBeavers = batchSize
        }
        
        dbSize := blocksPerRow*batchSize*16
        
        //data structure for holding batch of messages
        //each entry will be of length blocksPerRow*16
        db := make([][]byte, batchSize)
        for i:= 0; i < batchSize; i++ {
            db[i] = make([]byte, blocksPerRow*16)
        }
        flatDB := make([]byte, dbSize)

        //set up running average for timing
        batchesCompleted := 0
        var totalTime, totalBlindMacTime, totalShuffleTime, totalRevealTime time.Duration
        
        numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)

        log.Printf("using %d threads", numThreads)
        if numThreads != 16 {
            log.Println("performance could be improved by using a batchSize divisible by 16")
        }
        
        setupConns := make([][]net.Conn, numServers)
        if leader {
            for i:=1; i < numServers; i++ {          
                setupConns[i] = make([]net.Conn, numThreads)
                for j:=0; j < numThreads; j++ {
                    setupConns[i][j], err = tls.Dial("tcp", addrs[i], conf)
                    if err != nil {
                        log.Println(err)
                        return 
                    }
                    readFromConn(setupConns[i][j], 4)
                    writeToConn(setupConns[i][j], intToByte(1))
                    defer setupConns[i][j].Close()
                }
            }
        } else {
            setupConns[0] = make([]net.Conn, numThreads)
            for j:=0; j < numThreads; j++ {
                setupConns[0][j], err = ln.Accept()
                if err != nil {
                    log.Println(err)
                    return
                }
                writeToConn(setupConns[0][j], intToByte(1))
                readFromConn(setupConns[0][j], 4)
                setupConns[0][j].SetDeadline(time.Time{})
            }
        }
        
        beaverBlocker := make(chan int, 2)
        beaverBlockerTwo := make(chan int, 2)
        beaverCBlocker := make(chan int)
        beaverCBlockerTwo := make(chan int)
        blocker := make(chan int, 5)
        deltaBlocker := make(chan int)
        expansionBlocker := make(chan int)
        hashBlocker := make(chan int)
        unflattenBlocker := make(chan int)
        
        for testCount:=0; testCount < 5; testCount++{
            runtime.GC()
            log.Println("server ready")
            //NOTE: since the purpose of this evaluation is to measure the performance once the servers have already received the messages from the client, I'm just going to have the lead server generate the client queries and pass them on to the others to save time
            //receiving client connections phase 
            if leader {
                leaderReceivingPhase(db, setupConns, msgBlocks+1, batchSize, pubKeys, messagingMode)
            } else {
                otherReceivingPhase(db, setupConns, numServers, msgBlocks+1, batchSize, pubKeys[serverNum], mySecKey, serverNum)
            }
            //runtime.GC()
            log.Println("starting processing of message batch")
            //processing phase
            //NOTE: in reality, the blind verification and aux server stuff could be done as messages arrive
            //this would speed up the processing time, esp. if the server were multithreaded
            //but I'm handling everything for a batch at once so I can report performance for processing a batch        
                        
            aInitial := make([]byte, 0) //not important for first server
            bFinal := make([]byte, 0) //not important for last server
            aAtPermTime := make([]byte, 0) //not important for last server
            delta := make([]byte, 0) //only important for last server
            pi := make([]int, 0)
            beaversA := make([]byte, 0)
            beaversB := make([]byte, 0)
            beaversC := make([]byte, 0)
            beaversATwo := make([]byte, 0)
            beaversBTwo := make([]byte, 0)
            beaversCTwo := make([]byte, 0)
            
            
            startTime := time.Now()
            
            //pick seeds for aInitial, bFinal, aAtPermTime, pi, and beaver shares a, b (for both sets of verifications)
            seeds := make([]byte, 128)
            _,err := rand.Read(seeds[:])
            if err != nil {
                log.Println("couldn't generate seed")
                panic(err)
            }
                    
            //send the seeds to aux server
            go func () {
                writeToConn(auxConn, seeds)
                blocker <- 1
            }()
            //seed expansion
            go func() {
                if !messagingMode {
                    expandDB(db, msgBlocks+1)
                }
                expansionBlocker <- 1
            }()
            //generate the shares for which seeds were sent to the aux server
            go func() {
                    beaversA = mycrypto.AesPRG(16*numBeavers, seeds[48:64])
                    beaverBlocker <- 1
            }()
            go func() {
                    beaversB = mycrypto.AesPRG(16*numBeavers, seeds[64:80])
                    beaverBlocker <- 1
            }()
            go func() {
                pi = mycrypto.GenPerm(batchSize, seeds[80:96])
                blocker <- 1
            }()
            go func() {
                if serverNum > 0 {
                    aInitial = mycrypto.AesPRG(dbSize, seeds[0:16])
                }
                blocker <- 1
            }()
            go func() {
                if serverNum != numServers - 1 {
                    bFinal = mycrypto.AesPRG(dbSize, seeds[16:32])
                }
                blocker <- 1
            }()
            go func() {
                if serverNum != numServers - 1 {
                    aAtPermTime = mycrypto.AesPRG(dbSize, seeds[32:48])
                }
                blocker <- 1
            }()
            go func() {
                    beaversATwo = mycrypto.AesPRG(16*batchSize, seeds[96:112])
                    beaverBlockerTwo <- 1
            }()
            go func() {
                    beaversBTwo = mycrypto.AesPRG(16*batchSize, seeds[112:128])
                    beaverBlockerTwo <- 1
            }()

            go func() {
                //read beaver triples and share translation stuff
                beaversC = readFromConn(auxConn, numBeavers*16)
                beaverCBlocker <- 1
                if serverNum == numServers - 1 {//read delta
                    delta = readFromConn(auxConn, dbSize)
                    deltaBlocker <- 1
                }
                
                if messagingMode {
                    beaversCTwo = readFromConn(auxConn, numBeavers*16)
                } else { //fewer beaver triples second time
                    beaversCTwo = readFromConn(auxConn, batchSize*16)
                }
                
                beaverCBlockerTwo <- 1
            }()
            
            //make sure all the beaver triple a/b parts are here before proceeding
            for i:=0; i < 2; i++ {
                <- beaverBlocker
            }
            
            //make sure seed expansion is done
            <- expansionBlocker

            //if numServers > 2, timing starts here, wait to have all aux stuff. If numServers == 2, timing starts earlier with processing phase
            if numServers > 2 {
                for i:=0; i < 5; i++ {
                    <- blocker
                }
                <- beaverCBlocker
                if serverNum == numServers - 1 {
                    <- deltaBlocker
                }
                for i:=0; i < 2; i++ {
                    <- beaverBlockerTwo
                }
                <- beaverCBlockerTwo
                
                startTime = time.Now()

            }

            blindMacStartTime := time.Now()
            
            //blind mac verification
            
            //expand the key shares into the individual mac key shares, mask them and the msg shares with part of a beaver triple
            maskedStuff := mycrypto.GetMaskedStuff(batchSize, msgBlocks+1, myNum, beaversA, beaversB, db, messagingMode, false)
            
            //everyone distributes shares and then merges them
            maskedShares := broadcastAndReceiveFromAll(maskedStuff, conns, serverNum)
                    
            mergedMaskedShares := mergeFlattenedDBs(maskedShares, numServers, len(maskedStuff))
            
            if numServers == 2 {
                <- beaverCBlocker
            }
            
            //everyone computes (computed mac - provided tag) shares
            macDiffShares := mycrypto.BeaverProduct(msgBlocks+1, batchSize, beaversC, mergedMaskedShares, db, leader, messagingMode, false, false)
            
            //broadcast shares
            finalMacDiffShares := broadcastAndReceiveFromAll(macDiffShares, conns, serverNum)
            
            //verify the mac differences come out to 0
            success := mycrypto.CheckSharesAreZero(batchSize, numServers, finalMacDiffShares)
            if !success {
                panic("blind mac verification failed")
            }
            
            
            blindMacElapsedTime := time.Since(blindMacStartTime)
            
            //make sure the self-computed share translation stuff is ready if numServers == 2
            if numServers == 2 {
                for i:=0; i < 5; i++ {
                    <- blocker
                }
            }
            
            shuffleStartTime := time.Now()
                
            //shuffle
            flatten(db, flatDB)
            if serverNum != 0 { //everyone masks their DB share and sends it to server 0

                mycrypto.AddOrSub(flatDB, aInitial, true)//false is for subtraction
                writeToConn(conns[0], flatDB)
            } else { //server 0 does the shuffle
                
                //receive all the values masked with aInitial
                for i:=1; i < numServers; i++ {
                    mycrypto.AddOrSub(flatDB, readFromConn(conns[i], dbSize), true)
                }
                
                //permute and apply delta, mask result and send to server 1
                flatDB = mycrypto.PermuteDB(flatDB, pi)
                mycrypto.AddOrSub(flatDB, aAtPermTime, true)
                writeToConn(conns[1], flatDB)
            }
            //the middle servers take turns shuffling
            if serverNum != 0 && serverNum != numServers - 1 {
                //complete the vector to be permuted (read from prev server)             
                sAtPermTime := readFromConn(conns[serverNum-1], dbSize)
                
                //permute and apply delta, mask and send to next server
                flatDB = mycrypto.PermuteDB(sAtPermTime, pi)
                mycrypto.AddOrSub(flatDB, aAtPermTime, true)
                writeToConn(conns[serverNum+1], flatDB)
            }
            //the last server shuffles
            if serverNum == numServers - 1 {
                //complete the vector to be permuted (read from prev server) 
                sAtPermTime := readFromConn(conns[serverNum-1], dbSize)
                
                //permute and apply delta
                flatDB = mycrypto.PermuteDB(sAtPermTime, pi)
                
                if numServers == 2 {
                    <- deltaBlocker
                }
                
                mycrypto.AddOrSub(flatDB, delta, true)
            }
            //bFinal is actually the db here for everyone except the final server
            if serverNum != numServers - 1 {
                flatDB = bFinal
            }
            
            shuffleElapsedTime := time.Since(shuffleStartTime)
            
            
            //second blind mac verification
            
            //unflatten DB
            for i:=0; i < numThreads; i++ {
                startI := i*chunkSize
                endI := (i+1)*chunkSize
                go func(startIndex, endIndex int) {
                    for j:=startIndex; j < endIndex; j++ {
                        db[j] = flatDB[j*blocksPerRow*16:(j+1)*blocksPerRow*16]
                    }
                    unflattenBlocker <- 1
                }(startI, endI)
            }
                
            
            //start the hash of the final DB here in the background
            hash := make([]byte, 0)
            go func() {
                //hash the whole db
                hash = mycrypto.Hash(flatDB)
                hashBlocker <- 1
            }()
            

            
            if numServers == 2 {
                for i:=0; i < 2; i++ {
                    <- beaverBlockerTwo
                }
            }
            
            for i:=0; i < numThreads; i++ {
                <-unflattenBlocker
            }
            
            //expand the key shares into the individual mac key shares, mask them and the msg shares with part of a beaver triple
            maskedStuff = mycrypto.GetMaskedStuff(batchSize, msgBlocks+1, myNum, beaversATwo, beaversBTwo, db, messagingMode, true)
            
            //everyone distributes shares and then merges them
            maskedShares = broadcastAndReceiveFromAll(maskedStuff, conns, serverNum)
                    
            mergedMaskedShares = mergeFlattenedDBs(maskedShares, numServers, len(maskedStuff))
            
            if numServers == 2 {
                <- beaverCBlockerTwo
            }
            
            //everyone computes (computed mac - provided tag) shares
            macDiffShares = mycrypto.BeaverProduct(msgBlocks+1, batchSize, beaversCTwo, mergedMaskedShares, db, leader, messagingMode, true, true)
                        
            //hash macDiffShares and distribute as a commitment. 
            hashedMacDiffShares := mycrypto.Hash(macDiffShares)
            allHashedMacDiffShares := broadcastAndReceiveFromAll(hashedMacDiffShares, conns, serverNum)
            
            //broadcast shares
            finalMacDiffShares = broadcastAndReceiveFromAll(macDiffShares, conns, serverNum)
            
            //check that the broadcasted shares match the commitment
            if !mycrypto.CheckHashes(allHashedMacDiffShares, finalMacDiffShares, len(macDiffShares), serverNum) {
                panic("mac hashes did not match")
            }
            
            //verify the macs come out to 0
            success = mycrypto.CheckSharesAreZero(numThreads, numServers, finalMacDiffShares)
            if !success {
                panic("blind mac verification two failed")
            }
            
            revealTimeStart := time.Now()
            
            
            //commit, reveal, mac verify, decrypt
            
            //make sure we're done hashing the DB
            <- hashBlocker
            
            //send out hash (commitments)
            hashes := broadcastAndReceiveFromAll(hash, conns, serverNum)
            
            //send out full DB after getting everyone's commitment
            flatDBs := broadcastAndReceiveFromAll(flatDB, conns, serverNum)

            //check that the received DBs match the received hashes
            if !mycrypto.CheckHashes(hashes, flatDBs, dbSize, serverNum) {
                panic("hashes did not match")
            }
            //merge DBs
            mergedDB := mergeFlattenedDBs(flatDBs, numServers, len(flatDB))
            
            _ = mergedDB
            /*The servers don't actually need to do this last step, the clients can do it 
            themselves, both when it's used for broadcast and messaging*/
            //check macs in merged DBs and decrypt
            //outputDB, ok := checkMacsAndDecrypt(mergedDB, numServers, msgBlocks+1, batchSize, messagingMode)
            //if !ok {
            //    panic("macs did not verify")
            //}
            //_ = outputDB 
            
            revealElapsedTime := time.Since(revealTimeStart)
            elapsedTime := time.Since(startTime)
            
            if leader{
                batchesCompleted++
                totalTime += elapsedTime
                totalBlindMacTime += blindMacElapsedTime
                totalShuffleTime += shuffleElapsedTime
                totalRevealTime += revealElapsedTime
            }
            
            //only the leader outputs the stats on the last round
            if leader && testCount == 4{

                //log.Println(outputDB);
                
                fmt.Printf("%d servers, %d msgs per batch, %d byte messages\n", numServers, batchSize, msgBlocks*16)
                if messagingMode {
                    fmt.Printf("Messaging mode\n")
                }
                fmt.Printf("blind mac time: %s, average: %s", blindMacElapsedTime, totalBlindMacTime/time.Duration(batchesCompleted))
                fmt.Printf("shuffle time: %s, average: %s", shuffleElapsedTime, totalShuffleTime/time.Duration(batchesCompleted))
                fmt.Printf("reveal time: %s, average: %s\n", revealElapsedTime, totalRevealTime/time.Duration(batchesCompleted))
                fmt.Printf("batches completed: %d\n", batchesCompleted)
                fmt.Printf("Time for this batch: %s\n", elapsedTime)
                fmt.Printf("Average time per batch: %s\n\n\n", totalTime/time.Duration(batchesCompleted))
                
                log.Printf("Average time per batch: %s\n\n\n", totalTime/time.Duration(batchesCompleted))
            }
            
        }
    }
}
