package main

import (
    "log"
    "crypto/tls"
    //"net"
    //"os"
    //"time"
    //"unsafe"
    //"io"
    //"crypto/rand"
    "golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    "strconv"
    "strings"
    
    //"mycrypto" //my crypto in crypto.go, the rest generated by Goff https://github.com/ConsenSys/goff

)

func aux (numServers, msgBlocks, batchSize int, leaderAddr string) {
    
    log.Println("This is the auxiliary server")

    
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
    
    for {
            
        //TODO read a byte on the connection from the leaderAddr
        
        //TODO generate the preprocessed information for all the parties
        
        //TODO encrypt the shares for the non-leader servers
        
        //TODO send all the stuff to the leader 
        
    }
 
}
