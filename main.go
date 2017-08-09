package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"

	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	MAX_WORKERS      = 50 // Maximum worker goroutines
	HOLDING_CAPACITY = 30 // Holding capacity of the channel
)

type Handshake struct {
	Raw        []byte
	Essid      []byte
	Bssid      []byte
	Cmac       []byte
	Snonce     []byte
	Anonce     []byte
	Eapol      []byte
	Eapol_size int
	Kver       int
	Kmic       []byte

	PMK  []byte
	PKE  []byte
	PTK  []byte
	MIC  []byte
	Pass string
}

type RH struct {
	Raw        []byte
	essid      []byte
	bssid      []byte
	cmac       []byte
	snonce     []byte
	anonce     []byte
	eapol      []byte
	eapol_size int
	kver       int
	kmic       []byte

	PKE []byte
}

func (self *RH) Essid() []byte {
	return self.essid
}
func (self *RH) Bssid() []byte {
	return self.bssid
}
func (self *RH) Cmac() []byte {
	return self.cmac
}
func (self *RH) Snonce() []byte {
	return self.snonce
}
func (self *RH) Anonce() []byte {
	return self.anonce
}
func (self *RH) Eapol() []byte {
	return self.eapol
}
func (self *RH) Eapol_size() int {
	return self.eapol_size
}
func (self *RH) Kver() int {
	return self.kver
}
func (self *RH) Kmic() []byte {
	return self.kmic
}

type Stat struct {
	mu  sync.Mutex
	Ctr int64
}

func (self *Stat) Speed() int64 {
	self.mu.Lock()
	defer func() {
		self.mu.Unlock()
		self.Ctr = 0
	}()

	return self.Ctr
}
func (self *Stat) inc() {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.Ctr++
}

var stat Stat

var _p = flag.String("p", "", "plain password")
var _hs = flag.String("hs", "", "path to (cap|hccap)")
var _w = flag.String("w", "", "path to wordlist")
var _o = flag.String("o", "", "path to output file")
var _t = flag.Int("t", 1, "threads")

func (self *RH) LoadFromFile(path string) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	self.Raw = data
	self.parse()
}

func (self *RH) parse() {
	// ap name
	for i := 0; i <= 35; i++ {
		if self.Raw[i] != byte(0) {
			self.essid = append(self.essid, self.Raw[i])
		}
	}

	// ap mac
	for i := 36; i <= 41; i++ {
		self.bssid = append(self.bssid, self.Raw[i])
	}

	// client mac
	for i := 42; i <= 47; i++ {
		self.cmac = append(self.cmac, self.Raw[i])
	}

	// snonce
	for i := 48; i <= 79; i++ {
		self.snonce = append(self.snonce, self.Raw[i])
	}

	// anonce
	for i := 80; i <= 111; i++ {
		self.anonce = append(self.anonce, self.Raw[i])
	}

	// eapol_size
	var tmp_eapol_size []byte
	for i := 368; i <= 371; i++ {
		tmp_eapol_size = append(tmp_eapol_size, self.Raw[i])
	}
	self.eapol_size = int(binary.LittleEndian.Uint32(tmp_eapol_size))

	// eapol
	var checker int
	for i := 112; i <= 367; i++ {
		checker++
		if checker <= self.eapol_size {
			self.eapol = append(self.eapol, self.Raw[i])
		}
	}

	var tmp_kver []byte
	tmp_kver = append(tmp_kver, self.Raw[372])
	if tmp_eapol_size[0] == byte(1) {
		self.kver = 1
	} else {
		self.kver = 2
	}

	for i := 376; i <= 391; i++ {
		self.kmic = append(self.kmic, self.Raw[i])
	}

}

func (self *RH) Dump() {
	fmt.Printf("essid: %s\nbssid: %x\nclient mac: %x\nsnonce: %x\nanonce: %x\neapol: %x\neapol size: %d\nkey ver: %d\nkey mic: %x\nPKE: %x\nPTK: %x\nMIC: %x\n**************",
		self.essid, self.bssid, self.cmac, self.snonce, self.anonce, self.eapol, self.eapol_size, self.kver, self.kmic, self.PKE)
}

func (self *Handshake) Dump() {
	fmt.Printf("essid: %s\nbssid: %x\nclient mac: %x\nsnonce: %x\nanonce: %x\neapol: %x\neapol size: %d\nkey ver: %d\nkey mic: %x\nPKE: %x\nPTK: %x\nMIC: %x\n",
		self.Essid, self.Bssid, self.Cmac, self.Snonce, self.Anonce, self.Eapol, self.Eapol_size, self.Kver, self.Kmic, self.PKE, self.PTK, self.MIC)
}

func (self *Handshake) getPMK(password string) {
	self.PMK = pbkdf2.Key([]byte(password), []byte(self.Essid), 4096, 32, sha1.New)
}
func (self *Handshake) getPTK() {
	for i := 0; i < 4; i++ {
		self.PKE[99] = byte(i)
		h := hmac.New(sha1.New, self.PMK)
		_, err := h.Write(self.PKE)
		if err != nil {
			log.Println("Fuck bleat")
			return
		}
		self.PTK = append(self.PTK, h.Sum(nil)...)
	}
}
func (self *Handshake) getMIC() error {
	if self.Kver == 2 {
		h := hmac.New(sha1.New, self.PTK[0:16])
		_, err := h.Write(self.Eapol)
		if err != nil {

			return err
		}
		self.MIC = h.Sum(nil)
	} else {
		h := hmac.New(md5.New, self.PTK[:16])
		_, err := h.Write(self.Eapol)
		if err != nil {
			log.Println("Fuck bleat")
			return err
		}
		self.MIC = h.Sum(nil)
	}
	return nil
}

func (self *Handshake) CheckPassword(password string) (bool, error) {
	var err error
	self.getPMK(password)
	self.getPTK()
	if err = self.getMIC(); err != nil {
		return false, err
	}
	if bytes.Compare(self.MIC[0:16], self.Kmic[0:16]) == 0 {
		return true, nil
	}
	return false, nil
}

func (self *RH) initPKE() {
	self.PKE = append(self.PKE, []byte("Pairwise key expansion")...)
	self.PKE = append(self.PKE, []byte{0}...)

	if bytes.Compare(self.cmac, self.bssid) < 0 {
		self.PKE = append(self.PKE, self.cmac...)
		self.PKE = append(self.PKE, self.bssid...)
	} else {
		self.PKE = append(self.PKE, self.bssid...)
		self.PKE = append(self.PKE, self.cmac...)
	}
	if bytes.Compare(self.snonce, self.anonce) < 0 {
		self.PKE = append(self.PKE, self.snonce...)
		self.PKE = append(self.PKE, self.anonce...)
	} else {
		self.PKE = append(self.PKE, self.anonce...)
		self.PKE = append(self.PKE, self.snonce...)
	}
	self.PKE = append(self.PKE, []byte{0}...)
}

func (hs *Handshake) Brute(check bool) {
	shard.inc()
	defer shard.dec()
	result, err := hs.CheckPassword(hs.Pass)
	stat.inc()
	if err != nil {
		log.Println("Failed to check...", err)
		os.Exit(-1)
	}

	if check {
		if result {
			fmt.Println("Password is valid")
		} else {
			fmt.Println("Password is invalid")
		}
		os.Exit(0)
	}

	if result {
		log.Printf("Found password: %s\n", hs.Pass)
		os.Exit(0)
	}
}

type Shard struct {
	mu    sync.Mutex
	space int
}

func (s *Shard) inc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.space++
}
func (s *Shard) dec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.space--
}

var shard Shard

func main() {
	var wg sync.WaitGroup
	var rh RH = RH{}
	activeHandshakes := make(chan *Handshake, HOLDING_CAPACITY)
	defer close(activeHandshakes)
	rh.LoadFromFile(*_hs)
	rh.initPKE()

	if *_p != "" && len(*_p) > 7 && len(*_p) < 64 {
		var tmpHs = Handshake{
			Essid:      rh.Essid(),
			Bssid:      rh.Bssid(),
			Anonce:     rh.Anonce(),
			Snonce:     rh.Snonce(),
			Eapol:      rh.Eapol(),
			Eapol_size: rh.Eapol_size(),
			Kmic:       rh.Kmic(),
			Kver:       rh.Kver(),

			PKE:  rh.PKE,
			Pass: strings.Trim(string(*_p), "\n\r"),
		}
		tmpHs.Brute(true)
		os.Exit(0)
	}

	file, err := os.Open(*_w)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}
	defer file.Close()

	go func() {
		for {
			log.Printf("Current speed: %d\n", stat.Speed()/5)
			time.Sleep(time.Second * 5)
		}
	}()

	for i := 0; i < MAX_WORKERS; i++ {
		wg.Add(1)
		go func() {
			for h := range activeHandshakes {
				h.Brute(false)
			}
			wg.Done()
		}()
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		password := scanner.Text()
		activeHandshakes <- &Handshake{
			Essid:      rh.Essid(),
			Bssid:      rh.Bssid(),
			Anonce:     rh.Anonce(),
			Snonce:     rh.Snonce(),
			Eapol:      rh.Eapol(),
			Eapol_size: rh.Eapol_size(),
			Kmic:       rh.Kmic(),
			Kver:       rh.Kver(),

			PKE:  rh.PKE,
			Pass: strings.Trim(string(password), "\n\r"),
		}
	}
	log.Println("Wordlist finished")
	wg.Wait()
}

func init() {
	flag.Parse()
	if *_p == "" && *_w == "" {
		log.Println("Chose a password or wordlist!")
		os.Exit(-1)
	}
	if *_hs == "" {
		log.Println("Chose target file")
		os.Exit(-1)
	}

}
