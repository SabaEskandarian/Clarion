# ShuffleCommunication
Metadata-hiding communication from shuffling secret-shared data


#### Usage

To run the system, run each of the following commands in order on each server

```
server [numServers] [msg length in blocks] [shuffle batch size] 0

server [numServers] [msg length in blocks] [shuffle batch size] -1 [server0addr:4443]

server [numServers] [msg length in blocks] [shuffle batch size] 1 [server0addr:4443]

...

client [server0addr:4443] [numServers] [msg length in blocks] [numMsgs] [numThreads]

```

* The implementation always uses port 4443, but this is easy to change if you want to run the system on another port

* `numServers` is the number of servers in the system. For the 1 out of 3 secure variant of the system, set numServers to 2 (server -1 doesn't count toward the total)

* `msg length in blocks` is the length of messages sent through the system in terms of 16 byte blocks

* `shuffle batch size` is the number of messages the servers must received before they do a shuffle

* `numMsgs` is the number of messages the client is to send. Each message is sent over a separate connection simulating a different client. 

* `numThreads` can generally just be set to 1. The client sends numMsgs * numThreads messages


#### Notes

The performance measurement for the 1 of 3 system starts when server -1 begins to prepare share translations and beaver triples. 

Performance measurement for k-1 of k system starts after the servers are sent the preprocessing information


#### Warning

Please do not use this software to secure 
real-world communications. The purpose of 
this software is to evaluate the performance 
of the system, so it is not hardened for sensitive applications



