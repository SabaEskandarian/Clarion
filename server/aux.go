package main

import (
    "log"
    "crypto/tls"
    "net"
    "time"
    "golang.org/x/crypto/nacl/box"
    "strconv"
    "strings"
    
    "shufflemessage/mycrypto" 
)

func aux (numServers, msgBlocks, batchSize int, addrs []string) {
    
    log.Println("This is the auxiliary server")
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    pubKeys := make([]*[32]byte, numServers)
    sharedKeys := make([][32]byte, numServers)
    
    var err error;
    
    _, mySecKey, err := box.GenerateKey(strings.NewReader(strings.Repeat("a", 10000)))
    if err != nil {
        log.Println(err)
        return
    }
    
    for i := 0; i < numServers; i++ {
    	pubKeys[i], _, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
    	if err != nil {
        	log.Println(err)
        	return
    	}
    	
    	box.Precompute(&sharedKeys[i], pubKeys[i], mySecKey)
    }
 
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to each server 
    //holds connections to the shuffle servers
    conns := make([]net.Conn, numServers)
    
    for i:=0; i < numServers; i++ {
        //connect to each server
        conns[i], err = tls.Dial("tcp", addrs[i], conf)
        if err != nil {
            log.Println(err)
            return
        }
        defer conns[i].Close()
        readFromConn(conns[i], 4)
    }

    
    blocksPerRow :=  msgBlocks + numServers + 2 //2 is for the mac and enc key, numServers for the mac key shares
        
    numBeavers := batchSize * (msgBlocks + 1) // +1 is for the encryption key which is included in the mac
    
    totalBatches := 0
    var totalTime time.Duration
    blocker := make(chan int)
    
    for {
        log.Println("ready")
        //leader requests triples and translations
        readFromConn(conns[0], 4)
        log.Println("received request")
            
        startTime := time.Now()
        
        //generate the preprocessed information for all the parties

        beavers := mycrypto.GenBeavers(numBeavers, numServers)
        
        perms, deltas, abs := mycrypto.GenShareTrans(batchSize, blocksPerRow, numServers)


        //send servers their stuff
        for i:= 0; i < numServers; i++ {
            go func(myBeavers, myPerm, myDelta []byte, abs [][][]byte, serverNum int) {
                writeToConn(conns[serverNum], myBeavers)
                writeToConn(conns[serverNum], myPerm)
                writeToConn(conns[serverNum], myDelta)
                for j:=0; j < numServers; j++ {
                    if j!= i {
                        writeToConn(conns[serverNum], abs[j][serverNum])
                    }
                }
                blocker <- 1
                return
            } (beavers[i], perms[i], deltas[i], abs, i)
        }
        
        for i:=0; i < numServers; i++ {
            <- blocker
        }
        

        
        elapsedTime := time.Since(startTime)
        totalTime += elapsedTime
        totalBatches++
        log.Printf("preprocessing data prepared in %s\n", elapsedTime)
        log.Printf("%d batches prepared so far, average time %s\n\n", totalBatches, totalTime/time.Duration(totalBatches))
    }
}
