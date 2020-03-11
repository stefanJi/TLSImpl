# TLSImpl

A simple implementation for TLS protocol(v1.2). 

### Target

Generate a master key by implement TLS handshake. And use the key to communicate with the server.

```
Client                                               Server

ClientHello                  -------->
                                                  ServerHello
                                                 Certificate*
                                           ServerKeyExchange*
                                        CertificateRequest*
                             <--------      ServerHelloDone
Certificate*
ClientKeyExchange
CertificateVerify*
[ChangeCipherSpec]
Finished                     -------->
                                         [ChangeCipherSpec]
                             <--------             Finished
Application Data             <------->     Application Data
```
### Client Flow

-[x] Client Hello
-[ ] Client Key Exchange
-[ ] Certificate Verify
-[ ] Change Cipher Spec
-[ ] Application Data

### Server Flow Parse

-[x] Server Hello
-[x] Certificate
-[ ] ServerHello
-[ ] Certificate
-[ ] ServerKeyExchang
-[x] ServerHelloDone
-[ ] ChangeCipherSpec
-[ ] Finished
-[ ] Application Data
