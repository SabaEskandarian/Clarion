package main

import (
    "log"
    "crypto/tls"
    "net"
    "time"
    "golang.org/x/crypto/nacl/box"
    "strconv"
    "strings"
    "runtime"
    
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
        writeToConn(conns[i], intToByte(1))
    }

    
    blocksPerRow :=  msgBlocks + numServers + 2 //2 is for the mac and enc key, numServers for the mac key shares
        
    numBeavers := batchSize * (msgBlocks + 1) // +1 is for the encryption key which is included in the mac
    
    totalBatches := 0
    var totalTime time.Duration
    var beaverTotalTime time.Duration
    blocker := make(chan int)
    deltaBlocker := make(chan int)
    seeds := make([][]byte, numServers)
    
    for testCount:=0; testCount < 10; testCount++{
        runtime.GC()
        log.Println("ready")
        
        for i:=0; i < numServers; i++ {
            go func(index int) {
                seeds[index] = readFromConn(conns[index], 96)
                blocker <- 1
            }(i)
        }
        
        for i:=0; i < numServers; i++ {
            <- blocker
        }
        
        log.Println("received requests")
            
        startTime := time.Now()
        
        //generate the preprocessed information for all the parties

        beavers := mycrypto.GenBeavers(numBeavers, seeds)
        
        //send servers their beaver stuff
        //no need for blocking since that next steps don't depend on this and there is blocking at the end
        for i:=0; i < numServers; i++ {
            go func(myBeavers []byte, serverNum int) {
                writeToConn(conns[serverNum], myBeavers)
                if serverNum == numServers - 1 {
                    deltaBlocker <- 1
                }
            }(beavers[i], i)
        }
        
        beaverElapsedTime := time.Since(startTime)
                
        //get the last delta
        delta := mycrypto.GenShareTrans(batchSize, blocksPerRow, seeds)
        
        //consume the delta blocker
        <- deltaBlocker
        //send the last server delta
        writeToConn(conns[numServers - 1], delta)
        
        elapsedTime := time.Since(startTime)
        totalTime += elapsedTime
        beaverTotalTime += beaverElapsedTime
        totalBatches++
        log.Printf("preprocessing data prepared in %s\n", elapsedTime)
        log.Printf("beaver generation time only: %s, average: %s\n", beaverElapsedTime, beaverTotalTime/time.Duration(totalBatches))
        log.Printf("%d batches prepared so far, average time %s\n\n", totalBatches, totalTime/time.Duration(totalBatches))
    }
}
