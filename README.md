coap: A CoAP publisher server/endpoint
=======================================

Author
-------
Robert Olsson <roolss@kth.se> and <robert@radio-sensors.com>

Introduction
------------
CoAP is an interesting protocol for IoT devices. The drawback has
been the RESTful approach to handle 6LoWPAN networks as still 
majority of hosts are ipv4-connected making it hard to access
nodes behind a NAT. 

The novel pub/sub draft addresses this by complementing the RESTful
approach with a broker part. A broker is out the 6LowPAN and a
client inside a 6LoPAN network can initiate a connection post or
publish data to the broker outside the 6LowPAN network.

The pub/sub draft enables further sharing via the broker to 
multiple users called subscribers. Different topics can be 
selected.

Note. This work is limited just to be an endpoint for a publisher 
and not to do data sharing broker functions. Often one just
has to send data in client to server like fashion with no 
or very controlled other users. 

Implementation.
--------------
All in standard C. No need for libraries nor classes. Should be
easy to port and extend. Can fork be a daemon.
 
Copyright
---------
GPL

Debugging
---------
A lot of effort has been put into debugging efforts. This to 
understand protocol and different options. Should be a useful
tool for protocol understanding.

Data storage
------------
Received data can be stored in data file for further analysis
plotting etc. Datafile example:

tail coap.dat 
2018-02-14 14:23:36 ps/fcc23d0000003c14/temp 21.62
2018-02-14 14:23:41 ps/fcc23d0000003c14/temp 21.62
2018-02-14 14:23:46 ps/fcc23d0000003c14/temp 21.62
2018-02-14 14:23:52 ps/fcc23d0000003c14(temp 21.62

Date/time and topic and payload is seen. The fcc23d0000003c14
in this case is the unique id of the sensor.

Command line options
--------------------
./coap -h 

Version 1.0 2018-02-11

coap: A CoAP pubsub server/endpoint
  * Logs pubsub data in file
  * Verbose protocol and option debugging
  * Plain C, no libs, no classes etc
  * GPL copyright

Usage: coap [-d] [-b] [-p port] [-gmt] [-u] [-f file]
 -f file      local logfile. Default is ./coap.dat
 -p port      TCP server port. Default 5683
 -b           run in background
 -d           debug
 -ut          add Unix time
 -gmt         time in GMT


Build
-----
make 
