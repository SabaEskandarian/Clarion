package main

import (
    "log"
    "crypto/tls"
    //"net"
    //"os"
    "time"
    //"unsafe"
    //"io"
    "crypto/rand"
    "golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
    "strings"
    
    "shufflemessage/mycrypto" 
)

func aux (numServers, msgBlocks, batchSize int, leaderAddr string) {
    
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
    
    //connect to server
    conn, err := tls.Dial("tcp", leaderAddr, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()
    
    var nonce [24]byte
    blocksPerRow :=  msgBlocks + numServers + 2 //2 is for the mac and enc key, numServers for the mac key shares
        
    numBeavers := batchSize * (msgBlocks + 1) // +1 is for the encryption key which is included in the mac
    
    totalBatches := 0
    var totalTime time.Duration
    
    for {
        //leader requests triples and translations
        readFromConn(conn, 4)
            
        startTime := time.Now()
        
        //generate the preprocessed information for all the parties

        beavers := mycrypto.GenBeavers(numBeavers, numServers)
        
        perms, deltas, abs := mycrypto.GenShareTrans(batchSize, blocksPerRow, numServers)

        //send leader server its stuff
        writeToConn(conn, beavers[0])
        writeToConn(conn, perms[0])
        writeToConn(conn, deltas[0])
        for j := 1; j < numServers; j++ {
            writeToConn(conn, abs[j][0])
        }
        
        //encrypt and send the shares for the non-leader servers
        for i := 1; i < numServers; i++ {
            //collect stuff to write to server i
            stuffToWrite := make([]byte, 0)
            stuffToWrite = append(stuffToWrite, beavers[i]...)
            stuffToWrite = append(stuffToWrite, perms[i]...)
            stuffToWrite = append(stuffToWrite, deltas[i]...)
            for j:=0; j < numServers; j++{
                if j!=i {
                    stuffToWrite = append(stuffToWrite, abs[j][i]...)
                }
            }
            
            //box stuffToWrite
            rand.Read(nonce[:])
            if err != nil {
                log.Println("couldn't generate nonce")
                panic(err)
            }
            
            box := box.SealAfterPrecomputation(nil, stuffToWrite, &nonce, &sharedKeys[i])
                        
            //send nonce and box to the leader
            writeToConn(conn, append(nonce[:], box...))
        }
        
        elapsedTime := time.Since(startTime)
        totalTime += elapsedTime
        totalBatches++
        log.Printf("preprocessing data prepared in %s\n", elapsedTime)
        log.Printf("%d batches prepared so far, average time %s\n\n", totalBatches, totalTime/time.Duration(totalBatches))
    }
}
