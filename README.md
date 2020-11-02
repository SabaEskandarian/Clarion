# ShuffleCommunication
Metadata-hiding communication from shuffling secret-shared data


#### Usage

To run the system, run each of the following command on each server, with serverNums in order 0, 1, 2, ..., k, -1. The paramFile you use should have k+1 servers.

```
server [serverNum] [paramFile]

```

On the client, run the following.

```

client [server0addr:port] [numServers] [msg length in blocks] [numMsgs] [numThreads]

```

* `numServers` is the number of servers in the system (k). For the 1 out of 3 secure variant of the system, set numServers to 2 (server -1 doesn't count toward the total)

* `msg length in blocks` is the length of messages sent through the system in terms of 16 byte blocks. This should match the number in the server params file

* `shuffle batch size` is the number of messages the servers must received before they do a shuffle. This should match the number in the server params file

* `numMsgs` is the number of messages the client is to send. Each message is sent over a separate connection simulating a different client. 

* `numThreads` can generally just be set to 1. The client sends numMsgs * numThreads messages

Run the client/server with no parameters for help.


#### Notes

The performance measurement for the 1 of 3 system starts when server -1 begins to prepare share translations and beaver triples. 

Performance measurement for k-1 of k system starts after the servers are sent the preprocessing information


#### Warning

Please do not use this software to secure 
real-world communications. The purpose of 
this software is to evaluate the performance 
of the system, so it is not hardened for sensitive applications



