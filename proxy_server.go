package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

func main() {

	key := pbkdf2.Key([]byte("proxy pass"), []byte("proxy salt"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	lis_port := os.Getenv("LIS_PORT")
	//svr_addr := os.Getenv("SVR_ADDR")
	// use_kcp := os.Getenv("USE_KCP")
	port, _ := strconv.Atoi(lis_port)
	if port < 1024 || port > 65530 {
		port = 6000
	}
	log.Println("server strt listen port:", port)
	// l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	l, err := kcp.ListenWithOptions(fmt.Sprintf(":%d", port), block, 10, 3)
	if err != nil {
		log.Panic(err)
	}
	session := 1
	for {
		//client, err := l.Accept()
		client, err := l.AcceptKCP()
		if err != nil {
			log.Panic(err)
		}
		//client.SetNoDelay(false)
		go handleClientRequest(client, session)
		session += 1
	}
}

func client_forward(src *kcp.UDPSession, dst net.Conn, aesKey string, session int) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE]byte
	readbyte := 0
	cnt := 1
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
			if readbyte < HEAD_SIZE {
				continue
			}
		}
		packet_len := BytesToInt(b[pos : pos+HEAD_SIZE])
		if pos+packet_len > PACKET_SIZE || packet_len <= 0 {
			log.Println("error cnt:", cnt, " pos:", pos, " readbyte:", readbyte, " packet_len:", packet_len)
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
		// 解密客户端的数据
		decryptData, err := decryptAES(b[pos:pos+packet_len], []byte(aesKey))
		if err != nil {
			log.Fatalln("encryptAES failed:", err)
			return
		}
		if _, err := dst.Write(decryptData[:]); err != nil {
			return
		}
		log.Println("seq:", cnt, " session:", aesKey, " send server encrpy len:", packet_len, " origlen", len(string(decryptData)))
		pos += packet_len
		buf_len := readbyte - pos
		for i := 0; i < buf_len; i++ {
			b[i] = b[pos+i]
		}
		readbyte -= pos
		if readbyte != 0 {
			log.Println("WARING session:", aesKey, " cnt:", cnt, " readbyte:", readbyte)
		}
		cnt++
	}
}

func server_forward(src net.Conn, dst *kcp.UDPSession, aesKey string) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE - 64]byte
	for {
		n, err := src.Read(b[:])
		if err != nil {
			//log.Println(err)
			return
		}
		if n <= 0 {
			continue
		}
		// 加密返回客户端
		encryptData, err := encryptAES(b[:n], []byte(aesKey))
		if err != nil {
			log.Println("encryptAES failed", err)
			return
		}
		length_byte := IntToBytes(len(string(encryptData)))
		if _, err = dst.Write(length_byte[:]); err != nil {
			return
		}
		if _, err = dst.Write(encryptData[:]); err != nil {
			return
		}
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

func ShakeHands(c net.Conn, publicKey, aesKey *string) error {
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
	log.Println("recv packet_len:", packet_len)
	if packet_len > PACKET_SIZE {
		log.Println("error readbyte:", readbyte, " packet_len:", packet_len)
		return errors.New(fmt.Sprintf("packet_len err:", packet_len))
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
	*publicKey = string(b[pos : pos+packet_len])
	pos += packet_len
	readbyte -= pos
	if readbyte != 0 {
		log.Println("err recv more byte")
		return errors.New("err recv more byte")
	}
	*aesKey = GetRandomString(16)
	ciphertext, err := RsaEncrypt([]byte(*aesKey), *publicKey)
	if err != nil {
		log.Println("RsaEncrypt failed:", err.Error())
		return errors.New(fmt.Sprintf("RSA encryption failed"))
	}
	byte_length := IntToBytes(len(ciphertext))
	var buffer bytes.Buffer
	buffer.Write(byte_length)
	buffer.Write([]byte(ciphertext))
	bbyte_res := buffer.Bytes()
	_, err = c.Write(bbyte_res[:])
	if err != nil {
		log.Println("write failed")
		return errors.New(fmt.Sprintf("write failed"))
	}
	// log.Println("ShakeHands sucess easkey:", *aesKey, " buff len:", len(bbyte_res))
	return nil
}

// func handleClientRequest(client net.Conn, session int) {
func handleClientRequest(client *kcp.UDPSession, session int) {
	if client == nil {
		return
	}
	defer client.Close()
	var publicKey, aesKey string
	err := ShakeHands(client, &publicKey, &aesKey)
	if err != nil {
		log.Fatalln("ShakeHands failed")
		return
	}

	var b [BUFF_SIZE]byte
	n := 0
	for {
		readbyte, err := client.Read(b[n:])
		if err != nil {
			log.Println(err)
			return
		}
		n += readbyte
		if n < HEAD_SIZE {
			continue
		}
		break
	}
	packet_len := BytesToInt(b[0:HEAD_SIZE])
	for {
		if n >= packet_len+HEAD_SIZE {
			break
		}
		readbyte, err := client.Read(b[n:])
		if err != nil {
			log.Println(err)
			return
		}
		n += readbyte
	}

	decryptData, err := decryptAES(b[HEAD_SIZE:n], []byte(aesKey))
	if err != nil {
		log.Println("decryptAES failed", err)
		return
	}
	var method, host, address string
	fmt.Sscanf(string(decryptData[:]), "%s%s", &method, &host)
	hostPortURL, err := url.Parse(host)
	if err != nil {
		log.Println(err)
		return
	}

	if hostPortURL.Opaque == "443" { //https访问
		address = hostPortURL.Scheme + ":443"
	} else { //http访问
		if strings.Index(hostPortURL.Host, ":") == -1 { //host不带端口， 默认80
			address = hostPortURL.Host + ":80"
		} else {
			address = hostPortURL.Host
		}
	}

	//获得了请求的host和port，就开始拨号吧
	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err)
		return
	}
	// server.SetNoDelay(false)
	log.Println("conn server:", address, " sucess")
	defer server.Close()
	if method == "CONNECT" {
		context := "HTTP/1.1 200 Connection established\r\n\r\n"
		res, err := encryptAES([]byte(context), []byte(aesKey))
		if err != nil {
			log.Fatalln("encryptAES failed", err)
			return
		}
		byte_length := IntToBytes(len(string(res)))
		if _, err = client.Write(byte_length[:]); err != nil {
			return
		}
		if _, err = client.Write(res[:]); err != nil {
			return
		}
	} else {
		server.Write(decryptData[:])
	}
	//进行转发
	go client_forward(client, server, aesKey, session)
	server_forward(server, client, aesKey)
	log.Println("close:", address)
}
