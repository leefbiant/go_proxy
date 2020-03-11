package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
)

const BUFF_SIZE = 8192
const HEAD_SIZE = 4
const PACKET_SIZE = BUFF_SIZE - HEAD_SIZE

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	l, err := net.Listen("tcp", ":6000")
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go handleClientRequest(client)
	}
}

func client_forward(src net.Conn, dst net.Conn) {
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
				log.Println(err)
				return
			}
			readbyte += ret
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
				fmt.Println(err)
				return
			}
			readbyte += ret
		}
		pos += HEAD_SIZE
		writebyte, err := dst.Write(b[pos : pos+packet_len])
		if err != nil {
			return
		}
		if writebyte != packet_len {
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

func server_forward(src net.Conn, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	var b [BUFF_SIZE]byte
	for {
		n, err := src.Read(b[HEAD_SIZE:])
		if err != nil {
			//log.Println(errrc
			return
		}
		if n <= 0 {
			continue
		}
		length_byte := IntToBytes(n)
		for index := 0; index < HEAD_SIZE; index++ {
			b[index] = length_byte[index]
		}
		packet_len := n
		n += HEAD_SIZE
		n, err = dst.Write(b[:n])
		if err != nil {
			//log.Println(err)
			return
		}
		log.Println("write packet_len:", packet_len)
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

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

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
	// fmt.Println("packet_len:", packet_len, " n:", n)
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

	var method, host, address string
	fmt.Sscanf(string(b[HEAD_SIZE:]), "%s%s", &method, &host)
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
	defer server.Close()
	if method == "CONNECT" {
		res := "HTTP/1.1 200 Connection established\r\n\r\n"
		byte_length := IntToBytes(len(res))
		var buffer bytes.Buffer
		buffer.Write(byte_length)
		buffer.Write([]byte(res))
		bbyte_res := buffer.Bytes()
		n, err = client.Write(bbyte_res[:])
		if err != nil {
			return
		}
	} else {
		server.Write(b[:n])
	}
	//进行转发
	// go io.Copy(server, client)
	// io.Copy(client, server)
	go client_forward(client, server)
	server_forward(server, client)
	log.Println("close:", address)
}
