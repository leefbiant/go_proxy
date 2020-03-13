package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
)

const BUFF_SIZE = 8192
const HEAD_SIZE = 4
const PACKET_SIZE = BUFF_SIZE - HEAD_SIZE

func main() {
	logFile, err := os.OpenFile("proxy_client.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0766)
	if err != nil {
		panic(err)
	}
	log.SetOutput(logFile) // 将文件设置为log输出的文件
	log.SetPrefix("[qSkipTool]")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	l, err := net.Listen("tcp", ":5000")
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

func ShakeHands(c net.Conn, privateKeyStr, publicKeyStr, aesKey *string) error {
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
func client_forward(src net.Conn, dst net.Conn, aesKey string) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE]byte
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
		if packet_len > PACKET_SIZE {
			log.Println("error cnt:", cnt, " readbyte:", readbyte, " packet_len:", packet_len)
			return
		}
		for readbyte < packet_len+HEAD_SIZE {
			ret, err := src.Read(b[readbyte:])
			if err != nil {
				log.Println(err)
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
		cnt++
	}
}

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	address := "127.0.0.1:6000"
	//获得了请求的host和port，就开始拨号吧
	server, err := net.Dial("tcp", address)
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
