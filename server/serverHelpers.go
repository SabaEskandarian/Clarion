package main

import (
    "log"
    "net"
    "golang.org/x/crypto/nacl/box"
    "io"
    "time"
    "crypto/rand"
    //"crypto/tls"
    
    "shufflemessage/mycrypto" 
)


//some utility functions used by the servers

func leaderReceivingPhase(db [][]byte, setupConns [][]net.Conn, msgBlocks, batchSize int,  pubKeys []*[32]byte, messagingMode bool) {
    //client connection receiving phase
    numServers := len(setupConns)
    
    //32 is for mac key share and mac, 16 bytes each
    shareLength := 32 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    //generate preliminary permutation
    seed := make([]byte, 16)
    _,err := rand.Read(seed)
    if err != nil {
        log.Println("couldn't generate seed")
        panic(err)
    }
    rand.Read(seed)
    prelimPerm := mycrypto.GenPerm(batchSize, seed)
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
                
                clientTransmission, _ := clientSim(msgCount%26, msgBlocks, pubKeys, messagingMode)
                
                //handle the message sent for this server
                copy(db[prelimPerm[msgCount]][0:shareLength], clientTransmission[0:shareLength])
                
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

func clientSim(msgType, msgBlocks int, pubKeys []*[32]byte, messagingMode bool) ([]byte, time.Duration) {
    startTime := time.Now()
    
    numServers := len(pubKeys)
        
    //generate the MACed ciphertext, MAC, and all the keys; secret share
    //look in vendors/mycrypto/crypto.go for details
    msg := mycrypto.MakeCT(msgBlocks-1, msgType)
    mac, keySeeds := mycrypto.WeirdMac(numServers, msg, messagingMode)
    bodyShares := mycrypto.Share(numServers, append(msg, mac...))
        
    //box shares with the appropriate key share seeds prepended
    //"box" sent to leader is actually just sent to the leader without a box
    msgToSend := append(bodyShares[0], keySeeds[0]...)
    
    //log.Printf("Msg length for one share: %d\n", len(msgToSend))
    //log.Printf("encryption size overhead: %d\n", box.AnonymousOverhead)
    
    for i:= 1; i < numServers; i++ {
        
        //SealAnonymous appends its output to msgToSend
        boxedMessage, err := box.SealAnonymous(nil, append(bodyShares[i], keySeeds[i]...), pubKeys[i], rand.Reader)
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
    shareLength := 32 + 16*msgBlocks
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
                
                //store in db
                copy(db[prelimPermIndex][0:shareLength], clientMessage[:])
            }
            
            blocker <- 1
        }(startIndex, endIndex, i)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
}

func expandDB(db [][]byte, msgBlocks int) {
    blocker := make(chan int)
    batchSize := len(db)
    numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)
    
    for i:=0; i < numThreads; i++ {
        startIndex := i*chunkSize;
        endIndex := (i+1)*chunkSize
        go func(startI, endI int) {
            for j:=startI; j < endI; j++ {
                copy(db[j][(msgBlocks+1)*16:], 
                     mycrypto.AesPRG(msgBlocks*16, db[j][(msgBlocks+1)*16:(msgBlocks+2)*16]))
            }
            blocker <- 1
        }(startIndex, endIndex)
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
            log.Println(n)
            panic(err)
        }
    }
    return buffer
}

func writeToConn(conn net.Conn, msg []byte) {
    n, err := conn.Write(msg)
    if err != nil {
        log.Println(n)
        panic(err)
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
func checkMacsAndDecrypt(mergedDB []byte, numServers, msgBlocks, batchSize int, messagingMode bool) ([][]byte, bool) {
    outputDB := make([][]byte, batchSize)
    rowLen := msgBlocks*32 + 16
    
    if messagingMode {
        rowLen = msgBlocks*16 + 32
    }
    
    success := true
    
    numThreads, chunkSize := mycrypto.PickNumThreads(batchSize)
    blocker := make(chan int)
    
    for t:=0; t < numThreads; t++ {
        startIndex := t*chunkSize
        endIndex := (t+1)*chunkSize
        go func(startI, endI int) {
            for i:=startI; i < endI; i++ {
                row := mergedDB[rowLen*i:rowLen*(i+1)]
                msg := row[:msgBlocks*16]
                tag := row[msgBlocks*16:(msgBlocks+1)*16]
                keys := row[(msgBlocks+1)*16:]

                if !mycrypto.CheckMac(msg, tag, keys, messagingMode) {
                    success = false
                }
                
                //decrypt
                msg = mycrypto.DecryptCT(msg)
                
                outputDB[i] = msg
            }
            blocker <- 1
        }(startIndex, endIndex)
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
    
    return outputDB, success
}

func broadcastAndReceiveFromAll(msg []byte, conns []net.Conn, myNum int) []byte {
    blocker := make(chan int)
    numServers := len(conns)
    contentLenPerServer := len(msg)
    content := make([]byte, contentLenPerServer*numServers)
        
    //for servers with lower number, read then write
    for i:=0; i < myNum; i++ {
        go func(data, outputLocation []byte, conn net.Conn) {
            bytesToRead := len(data)
            copy(outputLocation, readFromConn(conn, bytesToRead))
            writeToConn(conn, data)
            blocker <- 1
            return
        }(msg, content[i*contentLenPerServer:(i+1)*contentLenPerServer], conns[i])
    }
    
    //for servers with higher number, write then read
    for i:= myNum+1; i < numServers; i++ {
        go func(data, outputLocation []byte, conn net.Conn) {
            bytesToRead := len(data)
            writeToConn(conn, data)
            copy(outputLocation, readFromConn(conn, bytesToRead))
            blocker <- 1
            return
        }(msg, content[i*contentLenPerServer:(i+1)*contentLenPerServer], conns[i])
    }
    
    //"receive" from self
    copy(content[contentLenPerServer*myNum:contentLenPerServer*(myNum+1)], msg[:])
    
    for i := 1; i < numServers; i++ {
        <- blocker
    }
    
    return content
}
