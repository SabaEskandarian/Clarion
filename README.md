# Clarion
Metadata-hiding communication from shuffling secret-shared data


#### Usage

To run the system, run the following command on each server, with serverNums in order 0, 1, 2, ..., k, -1. The paramFile you use should have k+1 servers.

```
server [serverNum] [paramFile]

```

ParamFile holds one parameter per line, as described below. running `./server help` will also print directions, and there are examples in this repository under `server/params/`. 

*  The first line is the number of servers `numServers` in the system (k). For the 1 out of 3 secure variant of the system, set numServers to 2 (server -1 doesn't count toward the total)

*  The second line is the number of different parameter sets to evaluate the system with (`numParams`)

*  Next there are at least `numServers` lines, each of which holds the address of the corresponding server in the form addr:port

*  The list is terminated by a line which only says `PARAMS`

*  Next there are at least `numParams` sets of three lines each:

   - First, either the word `messaging` or `standard` to indicate the evaluation mode. In messaging mode, only the first block of each message is MACed.
   
   - Second, the number of 16-byte blocks in each message
   
   - Third, the number of messages in a shuffling batch


#### Notes

The performance measurement for the 1 of 3 system starts when server -1 begins to prepare share translations and beaver triples. 

Performance measurement for k-1 of k system starts after the servers are sent the preprocessing information

Each set of evaluation parameters are run 5 times, and the average is reported. 

To evaluate on a system with more than 16 cores, modify the `PickNumThreads` function accordingly in `mycrypto/crypto.go`.

#### Warning

Please do not use this software to secure 
real-world communications. The purpose of 
this software is to evaluate the performance 
of the system, so it is not hardened for sensitive applications



