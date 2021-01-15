package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

var (
	svr_addr string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	svr_addr = os.Getenv("SVR_ADDR")
	lis_port := os.Getenv("LIS_PORT")
	port, _ := strconv.Atoi(lis_port)
	if port < 1024 || port > 65530 {
		port = 5700
	}
	log.Println("server strt listen port:", port, " svr addr:", svr_addr)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}
		// client.SetNoDelay(false)
		go handleClientRequest(client)
	}
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

// 字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}

// func ShakeHands(c net.Conn, privateKeyStr, publicKeyStr, aesKey *string) error {
func ShakeHands(c *kcp.UDPSession, privateKeyStr, publicKeyStr, aesKey *string) error {
	err := GenRsaKey(1024, privateKeyStr, publicKeyStr)
	if err != nil {
		log.Fatalln("GenRsaKey failed")
		return err
	}
	byte_length := IntToBytes(len(*publicKeyStr))
	var buffer bytes.Buffer
	buffer.Write(byte_length)
	buffer.Write([]byte(*publicKeyStr))
	bbyte_res := buffer.Bytes()
	_, err = c.Write(bbyte_res[:])
	if err != nil {
		return err
	}
	var b [BUFF_SIZE]byte
	readbyte := 0
	pos := 0
	for {
		if readbyte > HEAD_SIZE {
			break
		}
		ret, err := c.Read(b[readbyte:])
		if err != nil {
			log.Println(err)
			return err
		}
		readbyte += ret
		if readbyte < HEAD_SIZE {
			continue
		}
	}
	packet_len := BytesToInt(b[pos : pos+HEAD_SIZE])
	if packet_len > PACKET_SIZE {
		log.Println("error readbyte:", readbyte, " packet_len:", packet_len)
		return err
	}
	for readbyte < packet_len+HEAD_SIZE {
		ret, err := c.Read(b[readbyte:])
		if err != nil {
			log.Println(err)
			return err
		}
		readbyte += ret
	}
	pos += HEAD_SIZE
	encrypAesKey := b[pos : pos+packet_len]
	aesKeyByte, err := RsaDecrypt(encrypAesKey, *privateKeyStr)
	if err != nil {
		log.Fatalln("rsa decrypt failed")
		return errors.New(fmt.Sprintf("rsa decrypt failed"))
	}
	*aesKey = string(aesKeyByte)
	pos += packet_len
	readbyte -= pos
	if readbyte != 0 {
		log.Println("err recv more byte")
		return errors.New("err recv more byte")
	}
	log.Println("ShakeHands sucess easkey:", *aesKey)
	return nil
}
func client_forward(src net.Conn, dst *kcp.UDPSession, aesKey string) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE - 64]byte
	cnt := 0
	for {
		n, err := src.Read(b[:])
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		// 加密发送到服务器
		encryptData, err := encryptAES(b[:n], []byte(aesKey))
		if err != nil {
			log.Fatalln("encryptAES failed", err)
			return
		}
		length_byte := IntToBytes(len(string(encryptData)))
		if _, err = dst.Write(length_byte[:]); err != nil {
			return
		}
		if _, err = dst.Write(encryptData[:]); err != nil {
			return
		}
		log.Println("seq:", cnt, " session:", aesKey, " client_forward byte:", len(string(encryptData)), " origlen:", n)
		cnt += 1
	}
}

func server_forward(src net.Conn, dst net.Conn, aesKey string) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE]byte
	readbyte := 0
	cnt := 0
	for {
		pos := 0
		for {
			if readbyte > HEAD_SIZE {
				break
			}
			ret, err := src.Read(b[readbyte:])
			if err != nil {
				//log.Println(err)
				return
			}
			readbyte += ret
			//log.Println("server_forward recv byte:", readbyte)
			if readbyte < HEAD_SIZE {
				continue
			}
		}
		packet_len := BytesToInt(b[pos : pos+HEAD_SIZE])
		if pos+packet_len > PACKET_SIZE || packet_len <= 0 {
			log.Println("error seq:", cnt, "session:", aesKey, " readbyte:", readbyte, " packet_len:", packet_len)
			return
		}
		for {
			if readbyte >= packet_len+HEAD_SIZE {
				break
			}
			ret, err := src.Read(b[readbyte:])
			if err != nil {
				fmt.Println(err)
				return
			}
			readbyte += ret
		}
		pos += HEAD_SIZE
		// 解密服务器返回的数据
		decryptData, err := decryptAES(b[pos:pos+packet_len], []byte(aesKey))
		if err != nil {
			log.Fatalln("AesDecrypt failed", err)
			return
		}
		_, err = dst.Write(decryptData[:])
		if err != nil {
			return
		}
		pos += packet_len
		buf_len := readbyte - pos
		for i := 0; i < buf_len; i++ {
			b[i] = b[pos+i]
		}
		readbyte -= pos
		if readbyte != 0 {
			log.Println("WARING session:", aesKey, " seq:", cnt, " readbyte:", readbyte)
		}
		cnt++
	}
}

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	address := svr_addr
	//获得了请求的host和port，就开始拨号吧
	key := pbkdf2.Key([]byte("proxy pass"), []byte("proxy salt"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)

	log.Println("recv conn start connect svr:", address)
	// server, err := net.Dial("tcp", address)
	server, err := kcp.DialWithOptions(address, block, 10, 3)
	if err != nil {
		log.Println(err)
		return
	}
	// server.SetNoDelay(false)
	defer server.Close()
	var privateKeyStr, publicKeyStr, aesKey string
	err = ShakeHands(server, &privateKeyStr, &publicKeyStr, &aesKey)
	if err != nil {
		log.Println("ShakeHands error")
		return
	}

	go client_forward(client, server, aesKey)
	server_forward(server, client, aesKey)
}
