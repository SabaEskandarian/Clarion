package main

import (
    "log"
    //"crypto/tls"
    //"net"
    "os"
    //"time"
    //"unsafe"
    //"io"
    //"crypto/rand"
    //"golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
)

func main() {
    
    numServers := 2
    msgBlocks := 5
    batchSize := 1000
    
    serverNum := 0
    addr:="127.0.0.1:4443"
    
    //leadServer = "127.0.0.1:4443"
    //auxServer = "127.0.0.1:4442"
    //otherServer = "127.0.0.1:4444"
    
    if len(os.Args) < 5 {
        log.Println("usage: server [numservers] [msg length in blocks] [shuffle batch size] [servernum] (if not leader, [leaderAddr])")
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
    
    
    log.SetFlags(log.Lshortfile)
    
    //listen for a connection from 
    
}

//NOTE, I'll require the order the servers go online to be leader, aux, and then the other servers in increasing index order. Otherwise we'll have problems. This'll just make the setup code easier. 

//main server will have a bunch of goroutines that will be open with all the other servers for handling client requests
//when its time to actually process, it will block the other goroutines and do all the important stuff in a main routine
