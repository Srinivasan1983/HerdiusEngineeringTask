package main

import (
	"HerdiusEngineeringTask/proto"
	"HerdiusEngineeringTask/trust"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type server struct{}

func main() {

	config := proto.GetSettings()

	lis, err := net.Listen("tcp", config.Address)
	if err != nil {
		log.Fatalf("Failed to listen: %s", config.Address)
	} else {
		fmt.Printf("Server Started: %v\n", config.Address)
	}

	var privatefile = "clientpriv"
	var publicfile = "clientpub"

	trust.GenerateRsaKeyPairIfNotExist(privatefile, publicfile, true)

	certFile := "cert/server.crt"
	keyFile := "cert/server.pem"
	creds, sslErr := credentials.NewServerTLSFromFile(certFile, keyFile)
	if sslErr != nil {
		log.Fatalf("Faild loading certificates %v\n", sslErr)
		return
	}
	serverOption := grpc.Creds(creds)
	s := grpc.NewServer(serverOption)

	proto.RegisterFindMaxNumServiceServer(s, &server{})
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}

}

func (*server) FindMaximumNum(stream proto.FindMaxNumService_FindMaximumNumServer) error {
	maxNumber := int32(0)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Fatalf("Error while reading number: %v", err)
			return err
		}

		codeStr := req.GetCodestr()
		clientPubKeyStr := req.GetClientpubkey()
		clientPubKey, err := trust.ParseRsaPublicKeyFromPemStr(clientPubKeyStr)
		if err != nil {
			log.Fatalf("Error while converting string pem to rsa type: %v", err)
			return err
		}

		privKey := trust.GetServerPrivateKey()
		signedMsg := req.GetSignature()

		value, err := trust.RSADecrypt(privKey, codeStr)
		if err != nil {
			log.Fatalf("Error while decrypting the request message: %v", err)
		}

		i, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			panic(err)
		}
		number := int32(i)
		if number < 0 {
			status.Errorf(
				codes.InvalidArgument,
				fmt.Sprintf("Received a negative number: %v", number),
			)
		}

		if reflect.TypeOf(number).Kind() != reflect.Int32 {
			status.Errorf(
				codes.Unknown,
				fmt.Sprintf("Received a unknown type: %v", number),
			)
		}

		var opts rsa.PSSOptions
		opts.SaltLength = rsa.PSSSaltLengthAuto

		newhash := crypto.SHA256
		h := newhash.New()
		h.Write([]byte(strconv.Itoa(int(number))))
		digest := h.Sum(nil)

		status := trust.VerifyPSS(clientPubKey, newhash, digest, signedMsg, &opts)

		if status {
			if number > maxNumber {
				maxNumber = number
				sendErr := stream.Send(&proto.FindMaximumNumResponse{Num: maxNumber})
				if sendErr != nil {
					log.Fatalf("Error while sending data to client stream: %v", err)
					return err
				} else {
					fmt.Printf("Verify Signature success for: %v\n", maxNumber)
				}
			}
		} else {
			fmt.Printf("Verify Signature failed: %v\n", status)
		}

	}

}
