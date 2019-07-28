package main

import (
	"HerdiusEngineeringTask/proto"
	"HerdiusEngineeringTask/trust"
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"strconv"

	"google.golang.org/grpc"
)

func main() {
	config := proto.GetSettings()

	cc, err := grpc.Dial(config.Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}

	defer cc.Close()

	c := proto.NewFindMaxNumServiceClient(cc)

	findMaxNumber(c)
}

func findMaxNumber(c proto.FindMaxNumServiceClient) {

	fmt.Println("Starting to do a Client Streaming RPC...")
	stream, err := c.FindMaximumNum(context.Background())
	if err != nil {
		log.Printf("Error while creating stream: %v", err)
		return
	}
	waitc := make(chan struct{})

	go func() {
		numbers := []int32{1, 5, 3, 6, 2, 20}
		log.Printf("Input Stream: %v\n", numbers)
		for idx, num := range numbers {
			// fmt.Println(os.Getwd())
			var privatefile = "clientpriv" + strconv.Itoa(idx)
			var publicfile = "clientpub" + strconv.Itoa(idx)

			trust.GenerateRsaKeyPairIfNotExist(privatefile, publicfile, true)

			pubKey := trust.GetServerPublicKey()

			codeStr, err := trust.RSAEncrypt(pubKey, strconv.Itoa(int(num)))
			if err != nil {
				log.Fatalf("Error while encrypting the request message: %v", err)
			}

			var opts rsa.PSSOptions
			opts.SaltLength = rsa.PSSSaltLengthAuto

			newhash := crypto.SHA256
			h := newhash.New()
			h.Write([]byte(strconv.Itoa(int(num))))
			digest := h.Sum(nil)

			privKey := trust.GetClientPrivateKey(privatefile)
			CpubKey := trust.GetClientPublicKey(publicfile)
			CpubKeyStr, _ := trust.ExportRsaPublicKeyAsPemStr(CpubKey)

			signBytes, err := trust.SignPSS(privKey, newhash, digest, &opts)
			if err != nil {
				log.Fatalf("Error while creating the signature: %v\n", err)
			}

			stream.Send(&proto.FindMaximumNumRequest{
				Num:          num,
				Codestr:      codeStr,
				Signature:    signBytes,
				Clientpubkey: CpubKeyStr,
			})
		}
		stream.CloseSend()
	}()

	go func() {
		for {
			res, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatalf("Error while receiving: %v", err)
				break
			}
			fmt.Printf("Received: %d\n", res.GetNum())
		}

		close(waitc)
	}()

	<-waitc

}
