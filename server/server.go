package main

import (
    "log"
    //"crypto/tls"
    "net"
    "os"
    //"time"
    //"unsafe"
    "io"
    //"crypto/rand"
    //"golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
    
    "shufflemessage/mycrypto" 
)

func main() {
    
    numServers := 2
    msgBlocks := 5
    batchSize := 1000
    
    serverNum := 0
    addr:="127.0.0.1:4443"
    
    log.SetFlags(log.Lshortfile)
        
    if len(os.Args) < 5 {
        log.Println("usage: server [numservers] [msg length in blocks] [shuffle batch size] [servernum] (if not leader, [leaderAddr:4443])")
        log.Println("set numServers to 2 for the 1 of 3 scheme. parameters must match for all servers")
        log.Println("server 0 is the leader")
        log.Println("server -1 is the aux server, tell that server the Addr of the leader")
        log.Println("servers 1... are the others, tell those servers the Addr of the leader")
        return
    } else {
        numServers, _ = strconv.Atoi(os.Args[1])
        msgBlocks, _ = strconv.Atoi(os.Args[2])
        batchSize, _ = strconv.Atoi(os.Args[3])
        serverNum, _ = strconv.Atoi(os.Args[4])
    }
    
    if serverNum == 0 { //leader
        leader(numServers, msgBlocks, batchSize)
    } else if len(os.Args) < 6 {
        log.Println("incorrect parameters, ask for help.")
        return
    } else { //not leader
        addr = os.Args[5]
        
        if serverNum == -1 { //aux server
            aux(numServers, msgBlocks, batchSize, addr)
        } else { //normal server
            server(numServers, msgBlocks, batchSize, serverNum, addr)
        }
    }
    
    //NOTE, I'll require the order the servers go online to be leader, aux, and then the other servers in increasing index order. Otherwise we'll have problems. This'll just make the setup code easier. 
}

//some utility functions used by the servers

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
