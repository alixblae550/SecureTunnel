// transparent_proxy — перехватывает TCP-соединения на уровне сетевого стека
// Windows с помощью WinDivert и прозрачно пересылает их через SecureTunnel
// SOCKS5-прокси (127.0.0.1:1080).
//
// Приложения не видят прокси — они думают, что подключаются напрямую.
//
// Сборка:
//   go mod tidy
//   go build -o transparent_proxy.exe .
//
// Запуск (от администратора, WinDivert.dll + WinDivert.sys в той же папке):
//   transparent_proxy.exe
//
// Остановка: Ctrl+C

package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/williamfhe/godivert"
)

const (
	// Порт нашего SecureTunnel SOCKS5-прокси
	socks5Host = "127.0.0.1"
	socks5Port = 1080

	// Порт, на котором слушает прозрачный прокси (внутренний)
	transparentPort = 1089

	// WinDivert фильтр: перехватываем исходящие TCP SYN (новые соединения)
	// не направленные на localhost и не направленные на наш порт
	divertFilter = "outbound and tcp and tcp.Syn and " +
		"not (ip.DstAddr >= 127.0.0.0 and ip.DstAddr <= 127.255.255.255)"
)

// connEntry хранит оригинальный dst для перехваченного соединения.
type connEntry struct {
	dstIP   net.IP
	dstPort uint16
}

var (
	connMap sync.Map // key: "srcIP:srcPort" → connEntry
)

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[tproxy] ")

	// Запускаем прозрачный SOCKS5-прокси-сервер
	go runTransparentServer()

	// Открываем WinDivert handle
	wd, err := godivert.NewWinDivertHandle(divertFilter)
	if err != nil {
		log.Fatalf("WinDivert open failed: %v\n"+
			"Убедитесь, что WinDivert.dll и WinDivert.sys находятся рядом с exe\n"+
			"и программа запущена от администратора.", err)
	}
	defer wd.Close()

	log.Printf("перехват TCP SYN активен → прозрачный прокси на :%d", transparentPort)
	log.Printf("SOCKS5 туннель: %s:%d", socks5Host, socks5Port)

	// Обработка сигнала завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("завершение...")
		wd.Close()
		os.Exit(0)
	}()

	// Основной цикл — читаем пакеты, подменяем dst, пересылаем
	for {
		packet, err := wd.Recv()
		if err != nil {
			// Handle может быть закрыт при завершении
			if err == io.EOF {
				break
			}
			log.Printf("recv error: %v", err)
			continue
		}

		go redirectPacket(wd, packet)
	}
}

// redirectPacket читает SYN-пакет, запоминает оригинальный dst,
// подменяет его на 127.0.0.1:transparentPort и отправляет обратно.
func redirectPacket(wd *godivert.WinDivertHandle, packet *godivert.Packet) {
	ipHdr := packet.Raw

	// Минимальная длина IPv4-заголовка: 20 байт
	if len(ipHdr) < 20 {
		_ = wd.Send(packet)
		return
	}

	// IPv4-заголовок
	ihl := int(ipHdr[0]&0x0F) * 4
	if len(ipHdr) < ihl+20 {
		_ = wd.Send(packet)
		return
	}

	srcIP := net.IP(ipHdr[12:16])
	dstIP := make(net.IP, 4)
	copy(dstIP, ipHdr[16:20])

	tcpHdr := ipHdr[ihl:]
	srcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHdr[2:4])

	key := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	connMap.Store(key, connEntry{dstIP: dstIP, dstPort: dstPort})

	// Подменяем назначение на 127.0.0.1:transparentPort
	copy(ipHdr[16:20], net.ParseIP("127.0.0.1").To4())
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(transparentPort))

	// Пересчитываем контрольные суммы
	packet.CalcNewChecksum(wd)

	if err := wd.Send(packet); err != nil {
		log.Printf("send error: %v", err)
	}
}

// runTransparentServer принимает перенаправленные TCP-соединения,
// узнаёт оригинальный dst из connMap и делает SOCKS5 CONNECT.
func runTransparentServer() {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", transparentPort))
	if err != nil {
		log.Fatalf("listen :%d: %v", transparentPort, err)
	}
	log.Printf("transparent proxy server listening on :%d", transparentPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handleConn(conn)
	}
}

// handleConn получает перенаправленное соединение, ищет оригинальный dst,
// устанавливает SOCKS5-соединение к SecureTunnel и проксирует данные.
func handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	// Определяем порт источника из входящего соединения
	srcAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	key := fmt.Sprintf("%s:%d", srcAddr.IP.String(), srcAddr.Port)

	val, ok := connMap.LoadAndDelete(key)
	if !ok {
		log.Printf("no entry for %s — dropping", key)
		return
	}
	entry := val.(connEntry)
	dstHost := entry.dstIP.String()
	dstPort := entry.dstPort

	log.Printf("transparent: %s -> %s:%d", key, dstHost, dstPort)

	// Подключаемся к SecureTunnel SOCKS5-прокси
	socks5Conn, err := dialSOCKS5(dstHost, dstPort)
	if err != nil {
		log.Printf("SOCKS5 connect to %s:%d failed: %v", dstHost, dstPort, err)
		return
	}
	defer socks5Conn.Close()

	// Двунаправленная пересылка данных
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(socks5Conn, clientConn)
		_ = socks5Conn.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, socks5Conn)
		_ = clientConn.(*net.TCPConn).CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// dialSOCKS5 устанавливает SOCKS5-соединение к (host, port) через наш прокси.
// Реализует RFC 1928: no-auth + CONNECT.
func dialSOCKS5(host string, port uint16) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", socks5Host, socks5Port), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5: %w", err)
	}

	// Приветствие: версия 5, 1 метод (no auth)
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}

	// Ответ сервера: должен быть {0x05, 0x00}
	resp := make([]byte, 2)
	if _, err = io.ReadFull(conn, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 auth failed: %v", resp)
	}

	// Запрос CONNECT: версия 5, cmd CONNECT, rsv 0, ATYP domain
	hostBytes := []byte(host)
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, 0x05, 0x01, 0x00, 0x03)
	req = append(req, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, byte(port>>8), byte(port))

	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Ответ: {ver, rep, rsv, atyp, ...}
	head := make([]byte, 4)
	if _, err = io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT refused (rep=0x%02x)", head[1])
	}

	// Пропускаем оставшуюся часть ответа (адрес + порт)
	switch head[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03: // domain
		n := make([]byte, 1)
		io.ReadFull(conn, n)
		io.ReadFull(conn, make([]byte, int(n[0])+2))
	case 0x04: // IPv6
		io.ReadFull(conn, make([]byte, 16+2))
	}

	return conn, nil
}
