package main

import (
    "log"
    "net"
    "golang.org/x/crypto/nacl/box"
    "io"
    "time"
    "shufflemessage/mycrypto" 
)


//some utility functions used by the servers

func leaderReceivingPhase(db [][]byte, conns []net.Conn, msgBlocks, batchSize int, ln net.Listener) {
    //client connection receiving phase
    //NOTE: this phase of server is currently single-threaded. 
    //Throughput could be significantly increased by making the servers handle multiple client requests concurrently
    numServers := len(conns)
    
    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    clientTransmissionLength := (numServers - 1) * boxedShareLength + shareLength
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
}

func otherReceivingPhase(db [][]byte, conn net.Conn, numServers, msgBlocks, batchSize int, myPubKey, mySecKey *[32]byte, myNum int) {

    //48 is for mac key share, mac, encryption key, 16 bytes each
    shareLength := 48 + 16*msgBlocks
    boxedShareLength := (shareLength + box.AnonymousOverhead)
    
    //client connection receiving phase
    for msgCount := 0; msgCount < batchSize; msgCount++ {
        
        //read permuted index from leader
        prelimPermIndex := byteToInt(readFromConn(conn, 4))
        
        //read client box from leader, unbox
        clientBox := readFromConn(conn, boxedShareLength)
        
        clientMessage, ok := box.OpenAnonymous(nil, clientBox, myPubKey, mySecKey)
        if !ok {
            panic("decryption not ok!!")
        }
        
        //expand seeds, store in db
        copy(db[prelimPermIndex][0:16*numServers], 
            mycrypto.ExpandKeyShares(myNum, numServers, clientMessage[0:16]))
        copy(db[prelimPermIndex][16*numServers:], clientMessage[16:shareLength])

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

func permuteDB(flatDB []byte, pi []int) []byte{
    rowLen := len(flatDB)/len(pi)

    permutedDB := make([]byte, len(flatDB))
    

    //permute
    for i:= 0; i < len(pi); i++ {
        copy(permutedDB[i*rowLen:(i+1)*rowLen], flatDB[pi[i]*rowLen:(pi[i]+1)*rowLen])
    }
    
    return permutedDB
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
    keyShares := make([][]byte, numServers)
    rowLen := msgBlocks*16 + 32 + numServers*16
    success := true
    
    //NOTE: this could probably be sped up by parallelizing the checking in chunks of rows
    for i:=0; i < batchSize; i++ {
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
