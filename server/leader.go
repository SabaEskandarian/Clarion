package main

import (
    "log"
    "crypto/tls"
    "net"
    //"os"
    "time"
    //"unsafe"
    //"io"
    //"crypto/rand"
    //"golang.org/x/crypto/nacl/box"
    //"sync/atomic"
    //"strconv"
)

func leader(numServers, msgBlocks, batchSize int) {
    //setup
    cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }
    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    port := ":4443"
    ln, err := tls.Listen("tcp", port, config)  
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()
    
    //first connection from Aux server
    auxConn, err := ln.Accept()
    if err != nil {
        log.Println(err)
        //continue
    }
    auxConn.SetDeadline(time.Time{})
        
    //holds connections to the body servers
    conns := make([]net.Conn, (numServers-1))

    for i := 0; i < numServers - 1; i++ {
        conns[i], err = ln.Accept()
        if err != nil {
            log.Println(err)
            return
        }
        conns[i].SetDeadline(time.Time{})
    }
            
    //TODO: handle connections from client one at a time, expand mac key, pass on shares to the correct servers with the correct index
    
    //TODO: when enough connections arrived, pause accepting connections, ping Aux, get preprocessing info, and pass on the information to each server
    
    //TODO: blind MAC verification, shuffle, real MAC verification
}
