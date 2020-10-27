package main

func server(numServers, msgBlocks, batchSize, myNum int, leaderAddr string) {
    
    
    //using a deterministic source of randomness for testing 
    //this is just for testing so the different parties share a key
    //in reality the public keys of the servers/auditors should be known 
    //ahead of time and those would be used
    pubKeys := make([]*[32]byte, numServers)
    
    var err error;
    
    
    for i := 0; i < numServers; i++ {
        
        if i == myNum {
            pubKeys[i], mySecKey, err := box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        } else {
            pubKeys[i], _, err = box.GenerateKey(strings.NewReader(strings.Repeat(strconv.Itoa(i),10000)))
            if err != nil {
                log.Println(err)
                return
            }
        }

    }
 
    conf := &tls.Config{
         InsecureSkipVerify: true,
    }
    
    //connect to server
    conn, err := tls.Dial("tcp", leaderAddr, conf)
    if err != nil {
        log.Println(err)
        return 0
    }
    defer conn.Close()
    
    for {
            
        //TODO read a byte from first server determining one of two message types
        //TODO client message or shuffling stuff, each of which needs to be handled

        
    }
}
