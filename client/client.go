package main

import (
    "log"
    "crypto/tls"
    //"unsafe"
    "time"
    //"crypto/rand"
    "golang.org/x/crypto/nacl/box"
    "strings"
    "os"
    "strconv"
)

var leadServer string

func main() {

	leadServer = "127.0.0.1:4443"
	
	msgBlocks := 2
	numServers := 2
	numMsgs := 1000
    numThreads := 1

    if len(os.Args) < 6 {
        log.Println("usage: client [leadServerIp:port] [numServers] [message length in blocks] [numMsgs] [numThreads]")
        log.Println("set numServers to 2 for the 1 of 3 scheme. message length and numServers must match the servers")
        return
    } else {
        leadServer = os.Args[1]
        numServers, _ = strconv.Atoi(os.Args[2])
        msgBlocks, _ = strconv.Atoi(os.Args[3])
        numMsgs, _ = strconv.Atoi(os.Args[4])
        numThreads, _ = strconv.Atoi(os.Args[5])
    }
    
    log.SetFlags(log.Lshortfile)
    
    if numServers < 2 {
    	log.Println("numServers must be at least 2")
    	return
    }
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    pubKeys := make([]*[32]byte, numServers)
    
    var err error;
    
    for i := 0; i < numServers; i++ {
    	pubKeys[i], _, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
    	if err != nil {
        	log.Println(err)
        	return
    	}
    }
    
    blocker := make(chan int)
    
    for i:=0; i < numThreads; i++ {
        
        //function to make a client connection and time the whole thing (per thread)
        go func(server string, threadNum, numMsgs, msgBlocks int, pubKeys []*[32]byte) {
            
            var totalTime time.Duration
            
            for i := 0; i < numMsgs; i++ {
            
                elapsedTime := clientConnection(server, msgBlocks, pubKeys);

                totalTime += elapsedTime
            }
            
            //This benchmarks only the crypto stuff, not the network parts
            log.Printf("Thread %d average write computation time (msg blocks: %d, num Msgs: %d): %s\n", threadNum, msgBlocks, numMsgs, totalTime/time.Duration(numMsgs))
            
            blocker <- 1
            return
            
        }(leadServer, i, numMsgs, msgBlocks, pubKeys)
        
    }
    
    for i:=0; i < numThreads; i++ {
        <- blocker
    }
}


func clientConnection(server string, msgBlocks int, pubKeys []*[32]byte) time.Duration {
    
     conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to server
    conn, err := tls.Dial("tcp", server, conf)
    if err != nil {
        log.Println(err)
        return 0
    }
    defer conn.Close()
    
    startTime := time.Now()
    
    msg := make([]byte, 4)//TODO temp, the final thing to be sent goes here

    
                    
    //TODO prepare the message
    
    //TODO split the message into shares
    
    //TODO box shares
    
    
    elapsedTime := time.Since(startTime)
    
    //send everything to server
    n, err := conn.Write(msg)
    if err != nil {
        log.Println(n, err)
        return 0
    }
    
    return elapsedTime
}
