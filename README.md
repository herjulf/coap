coap: A server and subscriber for the CoAP pub/sub protocol
===========================================================

Author
-------
Robert Olsson <roolss@kth.se> and <robert@radio-sensors.com>

Introduction
------------
CoAP [1] is an interesting protocol for IoT devices. The drawback has
been the RESTful approach to handle 6LoWPAN networks as still 
majority of hosts are ipv4-connected making it hard to access
nodes behind a NAT. Also as sensor nodes are constrained in may
ways there are reasons to to hide from exposure. Security 
issues is another strong motivation for the pub/sub approach.
The novel pub/sub draft [2] addresses this by complementing the RESTful
approach by adding a new broker function. The broker is outside the 
6LowPAN. The client is inside 6LoPAN network initiates the connection 
to post or publish data to the broker. The pub/sub draft enables further 
sharing via the broker to multiple users called subscribers. Different 
topics can be selected.

Server vs broker
----------------

This work is limited just to be an endpoint for a publisher and not to 
do data sharing broker functions. Often one just has to send data in 
client to server like fashion with no or very controlled other users. 

Implementation
--------------
All in standard C. No need for libraries nor classes. Should be easy 
to port and extend. Can fork be a daemon. This code is tested with 
the pub/sub implementation the Contiki-OS [3] the repository from [4] 
was used. 
 
Copyright
---------
GPL

Debugging
---------
A lot of effort has been put into debugging support. This to understand 
protocol and different options. Should be a useful tool for protocol 
understanding and experiments.

Data storage
------------
Received data can be stored in data file for further procssed, analysis 
plotting etc. Datafile example:

<pre>
tail coap.dat 
     2018-02-14 14:23:36 ps/fcc23d0000003c14/temp 21.62
     2018-02-14 14:23:41 ps/fcc23d0000003c14/temp 21.62
     2018-02-14 14:23:46 ps/fcc23d0000003c14/temp 21.62
     2018-02-14 14:23:52 ps/fcc23d0000003c14(temp 21.62
</pre>

Date/time and topic and payload is seen. The fcc23d0000003c14
in this case is the unique EUI64 address of the sensor

Command line options
--------------------
<pre>
coap -h

Version 1.3 2018-05-30

coap: A CoAP pubsub server/endpoint
  * A simple CoAP pubsub subscriber
  * Logs pubsub data in file
  * Verbose protocol and option debugging
  * Plain C, no libs, no classes etc
  * GPL copyright

coap [-d] [-b] [-p port] [-gmt] [-s broker] [-u uri] [-f file]
 -f file      local logfile. Default is ./coap.dat
 -p port      TCP server port. Default 5683
 -b           run in background
 -u           subscribe uri
 -s           subscribe host/broker
 -d           debug
 -ut          add Unix time
 -gmt         time in GMT
</pre>


Build
-----
make 


Future work
-----------
Program is not a full implemenation of the specs rather it's implemented on per need basis. 


References
----------
[1] RTC 7252  The Constrained Application Protocol (CoAP)  
[2] draft-ietf-core-coap-pubsub-03 Publish-Subscribe Broker for the Constrained Application Protocol  
[3] Publish-Subscribe Communication for CoAP. Contki-OS implementation. Jussi Haikara, KTH.  
[4] https://github.com/posjodin/contiki Contiki-OS with pub/sub  