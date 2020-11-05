package main

import (
    "log"
    "net"
    "golang.org/x/crypto/nacl/box"
    "io"
    "time"
    "crypto/rand"
    
    "shufflemessage/mycrypto" 
)


//some utility functions used by the servers

func leaderReceivingPhase(db [][]byte, setupConns [][]net.Conn, msgBlocks, batchSize int,  pubKeys []*[32]byte) {
    //client connection receiving phase
    numServers := len(setupConns)
    
    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    //generate preliminary permutation
    prelimPerm := mycrypto.GenPerm(batchSize)
    //NOTE: the preliminary permutation is effectively "for free" to evaluate because the server just copies the client messages into their permuted indices directly
    
    
    numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)
    //numThreads = 1
    //chunkSize = batchSize
    blocker := make(chan int)
    
    for i:=0; i < numThreads; i++ {
        startIndex := i*chunkSize
        endIndex := (i+1)*chunkSize
        go func(startI, endI, threadNum int) {
            //for performance measurement we'll only implement the case where all client messages are good
            //we'll just panic later if a blind mac verification fails
                        
            for msgCount := startI; msgCount < endI; msgCount++ {
                //handle connections from client, pass on boxes
                
                clientTransmission, _ := clientSim(msgCount%26, msgBlocks, pubKeys)
                
                //handle the message sent for this server
                copy(db[prelimPerm[msgCount]][0:16*numServers], 
                    mycrypto.ExpandKeyShares(0, numServers, clientTransmission[0:16]))
                copy(db[prelimPerm[msgCount]][16*numServers:], clientTransmission[16:shareLength])
                
                //pass on the boxes to the other servers, send the index they should be placed in too
                for i := 1; i < numServers; i++ {
                    
                    //send prelimPerm[msgCount]
                    writeToConn(setupConns[i][threadNum], intToByte(prelimPerm[msgCount]))
                    
                    //send client message
                    start := shareLength + (i-1)*boxedShareLength
                    end := shareLength + i*boxedShareLength
                    writeToConn(setupConns[i][threadNum], clientTransmission[start:end])
                }
            }
            blocker <- 1
        }(startIndex, endIndex, i)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
}

func clientSim(msgType, msgBlocks int, pubKeys []*[32]byte) ([]byte, time.Duration) {
    startTime := time.Now()
    
    numServers := len(pubKeys)
        
    //generate the MACed ciphertext, MAC, and all the keys; secret share
    //look in vendors/mycrypto/crypto.go for details
    keyAndCt := mycrypto.MakeCT(msgBlocks, msgType)
    mac, keyShareSeeds := mycrypto.WeirdMac(numServers, keyAndCt)
    bodyShares := mycrypto.Share(numServers, append(mac, keyAndCt...))
        
    //box shares with the appropriate key share seeds prepended
    //"box" sent to leader is actually just sent to the leader without a box
    msgToSend := append(keyShareSeeds[0],bodyShares[0]...)
    
    //log.Printf("Msg length for one share: %d\n", len(msgToSend))
    //log.Printf("encryption size overhead: %d\n", box.AnonymousOverhead)
    
    for i:= 1; i < numServers; i++ {
        
        //SealAnonymous appends its output to msgToSend
        boxedMessage, err := box.SealAnonymous(nil, append(keyShareSeeds[i],bodyShares[i]...), pubKeys[i], rand.Reader)
        if err != nil {
            panic(err)
        }
        msgToSend = append(msgToSend, boxedMessage...)
    }
    
    
    elapsedTime := time.Since(startTime)
    
    return msgToSend, elapsedTime
}

func otherReceivingPhase(db [][]byte, setupConns [][]net.Conn, numServers, msgBlocks, batchSize int, myPubKey, mySecKey *[32]byte, myNum int) {

    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)
    //numThreads = 1
    //chunkSize = batchSize
    
    blocker:= make(chan int)
    
    for i:=0; i < numThreads; i++ {
        startIndex := i*chunkSize
        endIndex := (i+1)*chunkSize
        go func(startI, endI, threadIndex int) {
            //client connection receiving phase
            for msgCount := startI; msgCount < endI; msgCount++ {
                
                //read permuted index from leader
                prelimPermIndex := byteToInt(readFromConn(setupConns[0][threadIndex], 4))
                
                //read client box from leader, unbox
                clientBox := readFromConn(setupConns[0][threadIndex], boxedShareLength)
                
                clientMessage, ok := box.OpenAnonymous(nil, clientBox, myPubKey, mySecKey)
                if !ok {
                    panic("decryption not ok!!")
                }
                
                //expand seeds, store in db
                copy(db[prelimPermIndex][0:16*numServers], 
                    mycrypto.ExpandKeyShares(myNum, numServers, clientMessage[0:16]))
                copy(db[prelimPermIndex][16*numServers:], clientMessage[16:shareLength])

            }
            
            blocker <- 1
        }(startIndex, endIndex, i)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
}

func readFromConn(conn net.Conn, bytes int) []byte {
    buffer := make([]byte, bytes)
    for count := 0; count < bytes; {
        n, err := conn.Read(buffer[count:])
        //log.Println(count)
        //log.Println(bytes)
        count += n
        if err != nil && err != io.EOF && count != bytes {
            log.Println(n, err)
        }
    }
    return buffer
}

func writeToConn(conn net.Conn, msg []byte) {
    n, err := conn.Write(msg)
    if err != nil {
        log.Println(n, err)
    }
}

func intToByte(myInt int) (retBytes []byte){
    retBytes = make([]byte, 4)
    retBytes[3] = byte((myInt >> 24) & 0xff)
    retBytes[2] = byte((myInt >> 16) & 0xff)
    retBytes[1] = byte((myInt >> 8) & 0xff)
    retBytes[0] = byte(myInt & 0xff)
    return
}

func byteToInt(myBytes []byte) (x int) {
    x = int(myBytes[3]) << 24 + int(myBytes[2]) << 16 + int(myBytes[1]) << 8 + int(myBytes[0])
    return
}

//flatten the db
func flatten(db [][]byte, flatDB []byte){
    rowLen := len(db[0])
    for i:= 0; i < len(db); i++ {
        copy(flatDB[i*rowLen:(i+1)*rowLen], db[i])
    }
}

func unflatten(db [][]byte, flatDB []byte) {
    rowLen := len(db[0])
    for i:=0; i < len(db); i++ {
        db[i] = flatDB[i*rowLen:(i+1)*rowLen]
    }
}

//merge the concatenation of flattened DBs into one DB
//by taking the elementwise sum of all the DBs
func mergeFlattenedDBs(flatDBs []byte, numServers, dbSize int) []byte {
    if dbSize % 16 != 0 || len(flatDBs) != numServers*dbSize {
        panic("something is wrong with the MergeFlattenedDBs parameters")
    }
    
    dbs := make([][]byte, numServers)
    
    for i := 0; i < numServers; i++ {
        dbs[i] = flatDBs[i*dbSize:(i+1)*dbSize]
    }
    
    return mycrypto.Merge(dbs)
}

//check all the macs in a merged db
//and decrypt the messages
func checkMacsAndDecrypt(mergedDB []byte, numServers, msgBlocks, batchSize int) ([][]byte, bool) {
    outputDB := make([][]byte, batchSize)
    rowLen := msgBlocks*16 + 32 + numServers*16
    success := true
    
    numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)
    blocker := make(chan int)
    
    for t:=0; t < numThreads; t++ {
        startIndex := t*chunkSize
        endIndex := (t+1)*chunkSize
        go func(startI, endI int) {
            keyShares := make([][]byte, numServers)
            for i:=startI; i < endI; i++ {
                row := mergedDB[rowLen*i:rowLen*(i+1)]
                for j:=0; j < numServers; j++ {
                    keyShares[j] = row[16*j:16*(j+1)]
                }
                tag := row[numServers*16:numServers*16+16]
                msg := row[numServers*16+16:]
                if !mycrypto.CheckMac(msg, tag, keyShares) {
                    success = false
                }
                outputDB[i] = mycrypto.DecryptCT(msg)
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    return outputDB, success
}

func receiveFromAll(myContribution []byte, conns []net.Conn, myNum int) []byte {
    blocker := make(chan int)
    numServers := len(conns)
    contentLenPerServer := len(myContribution)
    content := make([]byte, contentLenPerServer*numServers)
    
    copy(content[contentLenPerServer*myNum:contentLenPerServer*(myNum+1)], myContribution[:])

    //receive from everyone
    for i := 0; i < numServers; i++ {
        if i == myNum {
            continue
        }
        
        go func(outputLocation []byte, conn net.Conn, bytesToRead int) {
            copy(outputLocation, readFromConn(conn, bytesToRead))
            blocker <- 1
            return
        }(content[i*contentLenPerServer:(i+1)*contentLenPerServer], conns[i], contentLenPerServer)
    }
    
    for i := 1; i < numServers; i++ {
        <- blocker
    }
    
    return content
}

//broadcast a message to everyone
func broadcast(msg []byte, conns []net.Conn, myNum int) {
    blocker := make(chan int)
    numServers := len(conns)
    
    //broadcast
    for i := 0; i < numServers; i++ {
        if i == myNum {
            continue
        }
        
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
