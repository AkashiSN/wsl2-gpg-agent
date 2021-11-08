package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/apenwarr/fixconsole"
	"github.com/lxn/win"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

const (
	// Windows constats
	invalidHandleValue = ^windows.Handle(0)
	pageReadWrite      = 0x4
	fileMapWrite       = 0x2

	// ssh-agent/Pageant constants
	agentMaxMessageLength = 8192
	agentCopyDataID       = 0x804e50ba
)

var (
	gpg                     = flag.String("gpg", "", "gpg mode")
	sourceGpgConfigBasepath = flag.String("sourceGpgConfigBasepath", "", "gpg config path on windows")
	ssh                     = flag.Bool("ssh", false, "ssh mode")
	winssh                  = flag.String("winssh", "", "windows ssh mode")

	failureMessage = [...]byte{0, 0, 0, 1, 5}
)

func main() {
	fixconsole.FixConsoleIfNeeded()
	flag.Parse()
	log.SetOutput(os.Stderr)

	done := make(chan bool, 1)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		switch sig {
		case os.Interrupt:
			log.Printf("Caught signal")
			done <- true
		}
	}()

	if *gpg != "" {
		sourceBasePath := *sourceGpgConfigBasepath
		// fallback to default location if not specified
		if sourceBasePath == "" {
			winHomeDir, err := os.UserHomeDir()
			if err != nil {
				log.Printf("failed to find user home dir: %s", err)
				return
			}
			sourceBasePath = filepath.Join(winHomeDir, "AppData", "Roaming", "gnupg")
		}

		gpgconn, err := createGPGConn(filepath.Join(sourceBasePath, *gpg))
		if err != nil {
			log.Print(err)
			return
		}

		go func() {
			defer gpgconn.Close()

			go func() {
				_, err := io.Copy(gpgconn, os.Stdin)
				if err != nil {
					log.Printf("Could not copy gpg data from wsl socket to win socket: %s", err)
					return
				}
			}()

			_, err := io.Copy(os.Stdout, gpgconn)
			if err != nil {
				log.Printf("Could not copy gpg data from win socket to wsl socket: %s", err)
				return
			}

			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *ssh {
		go func() {
			handleSSH(bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout), func() {})

			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *winssh != "" {
		pipe, err := createNamedPipe(*winssh)
		if err != nil {
			log.Print(err)
			return
		}

		go func() {
			listenLoop(pipe, handleSSH)

			// If for some reason our listener breaks, kill the program
			done <- true
		}()
	}

	if *gpg == "" && !*ssh && *winssh == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Wait until we are signalled as finished
	<-done

	log.Print("Exiting...")
}

func createGPGConn(socketPath string) (net.Conn, error) {
	var port int
	var nonce [16]byte

	file, err := os.Open(socketPath)
	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(file)
	tmp, _, _ := reader.ReadLine()
	port, _ = strconv.Atoi(string(tmp))
	n, err := reader.Read(nonce[:])
	if err != nil {
		log.Printf("Could not read port from gpg nonce: %s", err)
		return nil, err
	}

	if n != 16 {
		err = fmt.Errorf("could not connet gpg: incorrect number of bytes for nonceRead incorrect number of bytes for nonce")
		log.Print(err)
		return nil, err
	}

	gpgConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Printf("Could not connet gpg: %s", err)
		return nil, err
	}

	_, err = gpgConn.Write(nonce[:])
	if err != nil {
		log.Printf("Could not authenticate gpg: %s", err)
		return nil, err
	}

	return gpgConn, nil
}

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, we need to be
// careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

type SecurityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      uint32
}

var queryPageantMutex sync.Mutex

func makeInheritSaWithSid() *windows.SecurityAttributes {
	var sa windows.SecurityAttributes

	u, err := user.Current()

	if err == nil {
		sd, err := windows.SecurityDescriptorFromString("O:" + u.Uid)
		if err == nil {
			sa.SecurityDescriptor = sd
		}
	}

	sa.Length = uint32(unsafe.Sizeof(sa))

	sa.InheritHandle = 1

	return &sa

}

func queryPageant(buf []byte) (result []byte, err error) {
	if len(buf) > agentMaxMessageLength {
		err = errors.New("message too long")
		return
	}

	var UTF16PtrFromString = func(s string) *uint16 {
		result, _ := syscall.UTF16PtrFromString(s)
		return result
	}

	hwnd := win.FindWindow(UTF16PtrFromString("Pageant"), UTF16PtrFromString("Pageant"))

	// Launch gpg-connect-agent
	if hwnd == 0 {
		log.Println("launching gpg-connect-agent")
		exec.Command("gpg-connect-agent", "reloadagent", "/bye").Run()
	}

	hwnd = win.FindWindow(UTF16PtrFromString("Pageant"), UTF16PtrFromString("Pageant"))
	if hwnd == 0 {
		err = errors.New("could not find Pageant window")
		return
	}

	// Adding process id in order to support parrallel requests.
	requestName := "WSLPageantRequest" + strconv.Itoa(os.Getpid())
	mapName := fmt.Sprint(requestName)
	queryPageantMutex.Lock()

	var sa = makeInheritSaWithSid()

	fileMap, err := windows.CreateFileMapping(invalidHandleValue, sa, pageReadWrite, 0, agentMaxMessageLength, UTF16PtrFromString(mapName))
	if err != nil {
		queryPageantMutex.Unlock()
		return
	}
	defer func() {
		windows.CloseHandle(fileMap)
		queryPageantMutex.Unlock()
	}()

	sharedMemory, err := windows.MapViewOfFile(fileMap, fileMapWrite, 0, 0, 0)
	if err != nil {
		return
	}
	defer windows.UnmapViewOfFile(sharedMemory)

	sharedMemoryArray := (*[agentMaxMessageLength]byte)(unsafe.Pointer(sharedMemory))
	copy(sharedMemoryArray[:], buf)

	mapNameWithNul := mapName + "\000"

	// We use our knowledge of Go strings to get the length and pointer to the
	// data and the length directly
	cds := copyDataStruct{
		dwData: agentCopyDataID,
		cbData: uint32(((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Len),
		lpData: ((*reflect.StringHeader)(unsafe.Pointer(&mapNameWithNul))).Data,
	}

	ret := win.SendMessage(hwnd, win.WM_COPYDATA, 0, uintptr(unsafe.Pointer(&cds)))
	if ret == 0 {
		err = errors.New("WM_COPYDATA failed")
		return
	}

	len := binary.BigEndian.Uint32(sharedMemoryArray[:4])
	len += 4

	if len > agentMaxMessageLength {
		err = errors.New("return message too long")
		return
	}

	result = make([]byte, len)
	copy(result, sharedMemoryArray[:len])

	return
}

func handleSSH(reader *bufio.Reader, writer *bufio.Writer, closer func()) {
	defer closer()

	for {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			log.Printf("io.ReadFull length error '%s'", err)
			return
		}

		len := binary.BigEndian.Uint32(lenBuf)
		log.Printf("Reading length: %v", len)
		buf := make([]byte, len)
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			log.Printf("io.ReadFull data error '%s'", err)
			return
		}

		log.Printf("Querying pageant")
		result, err := queryPageant(append(lenBuf, buf...))
		if err != nil {
			// If for some reason talking to Pageant fails we fall back to
			// sending an agent error to the client
			log.Printf("Pageant query error '%s'", err)
			result = failureMessage[:]
		}

		_, err = writer.Write(result)
		if err != nil {
			log.Printf("net.Conn.Write error '%s'", err)
			return
		}

		writer.Flush()
	}
}

func listenLoop(ln net.Listener, handler func(*bufio.Reader, *bufio.Writer, func())) {
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("net.Listener.Accept error '%s'", err)
			return
		}

		log.Printf("New connection: %v\n", conn)

		closer := func() {
			conn.Close()
		}

		go handler(bufio.NewReader(conn), bufio.NewWriter(conn), closer)
	}
}

func createNamedPipe(pipeName string) (net.Listener, error) {
	namedPipeFullName := "\\\\.\\pipe\\" + pipeName
	var cfg = &winio.PipeConfig{}
	pipe, err := winio.ListenPipe(namedPipeFullName, cfg)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Could not open named pipe %s", namedPipeFullName))
	}

	log.Printf("Listening on named pipe: %s", namedPipeFullName)

	return pipe, nil
}
