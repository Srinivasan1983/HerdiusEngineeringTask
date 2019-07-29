# HerdiusEngineeringTask

# Solution Handled
* Use GRPC with Bi-directional streaming mode.
* generate keypair for every client request and one keypair for server using RSA algo.
* Every requested message from client are encrypted with server public key, self signed with each    privatekey.
* on Server side each requested messages are decrypt with server privatekey and verified with each   client public key.
* MaxNumber logic performed only for sucessfully verified message and respond to client.

# To Run at localhost
* Run go get github.com/Srinivasan1983/HerdiusEngineeringTask
* From working directory HerdiusEngineeringTask
* Run go run server/server.go for server.
* And go run client/client.go for client.

    * Input - Output Client side
        Starting to do a Client Streaming RPC...
        2019/07/29 09:53:14 Input Stream: [1 5 3 6 2 20]
        Received: 1
        Received: 5
        Received: 6
        Received: 20

    * Server Log Output 
        Verify Signature success for: 1
        Verify Signature success for: 5
        Verify Signature success for: 6
        Verify Signature success for: 20



# ToDo
* I want to handle TLS/SSL for encrpted client/server communication
* I need to write test cases.