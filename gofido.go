package gofido

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/text/encoding/charmap"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// FidoNetAddress structure of FidoNet address zone:network/node.point@domain
type FidoNetAddress struct {
	Zone    uint16
	Network uint16
	Node    uint16
	Point   uint16
	Domain  string
}

// FidoMessage implements simple Message architecture
type FidoMessage struct {
	FromName   string
	FromAddr   FidoNetAddress
	ToName     string
	ToAddr     FidoNetAddress
	Subj       string
	Text       string
	DateTime   time.Time
	Attributes uint16
}

// PktHeader header of standard .pkt file
type PktHeader struct {
	OrigNode   uint16  // of packet, not of messages in packet
	DestNode   uint16  // of packet, not of messages in packet
	Year       uint16  // of packet creation, e.g. 1986
	Month      uint16  // of packet creation, 0-11 for Jan-Dec
	Day        uint16  // of packet creation, 1-31
	Hour       uint16  // of packet creation, 0-23
	Minute     uint16  // of packet creation, 0-59
	Second     uint16  // of packet creation, 0-59
	Baud       uint16  // max baud rate of orig and dest, 0=SEA
	PacketType uint16  // old type-1 packets now obsolete
	OrigNet    uint16  // of packet, not of messages in packet
	DestNet    uint16  // of packet, not of messages in packet
	ProdCode   byte    // 0 for Fido, write to FTSC for others
	SerialNo   byte    // binary serial number (otherwise null)
	Password   [8]byte // session password  (otherwise null)
	OrigZone   uint16  // zone of pkt sender (otherwise null)
	DestZone   uint16  // zone of pkt receiver (otherwise null)
	Filled     [20]byte
}

type pktMsgHeader struct {
	OrigNode      uint16 // of message
	DestNode      uint16 // of message
	OrigNet       uint16 // of message
	DestNet       uint16 // of message
	AttributeWord uint16
	Cost          uint16   // in lowest unit of originator's currency
	DateTime      [20]byte // message body was last edited
}

const (
	// PktUserNameSize maximum size of null terminated User Name variable
	PktUserNameSize = 36
	// PktSubjectSize maximum size of null terminated Subject variable
	PktSubjectSize = 72
	// PktTextSize maximum size of null terminated Text variable (Body of the message)
	PktTextSize = 65535
	// PktDateTimeLayout parsing time layout
	PktDateTimeLayout = "02 Jan 06  15:04:05"
)

// ReFidoNetAddress regular expression matches standard FidoNet address string
var ReFidoNetAddress = regexp.MustCompile(`^(\d{1,4}):(\d{1,5})/(\d{1,5})[.]?(\d{1,5})?[@]?([a-z]*)$`)

// ParseAddress parses a string with FidoNet address and returns it's separate elements
func ParseAddress(strAddr string) (fAddress FidoNetAddress, err error) {
	if ReFidoNetAddress.MatchString(strAddr) == false {
		err = fmt.Errorf("FidoNet address pattern didn't match: %v", strAddr)
		return
	}

	var zone, network, node, point uint64
	var domain string

	s := ReFidoNetAddress.FindStringSubmatch(strAddr)

	if zone, err = strconv.ParseUint(s[1], 10, 16); err != nil {
		return
	}
	if network, err = strconv.ParseUint(s[2], 10, 16); err != nil {
		return
	}
	if node, err = strconv.ParseUint(s[3], 10, 16); err != nil {
		return
	}
	if len(s) > 3 && s[4] != "" {
		if point, err = strconv.ParseUint(s[4], 10, 16); err != nil {
			return
		}
	} else {
		point = 0
	}

	if len(s) > 4 && s[5] != "" {
		domain = s[5]
	}

	fAddress = FidoNetAddress{
		uint16(zone),
		uint16(network),
		uint16(node),
		uint16(point),
		domain}
	return
}

// ComposeAddress makes FidoNet address string from FidoNetAddress struct
func ComposeAddress(fAddr FidoNetAddress) (strAddr string) {
	strAddr = strconv.Itoa(int(fAddr.Zone))
	strAddr += ":" + strconv.Itoa(int(fAddr.Network))
	strAddr += "/" + strconv.Itoa(int(fAddr.Node))
	if fAddr.Point != 0 {
		strAddr += "." + strconv.Itoa(int(fAddr.Point))
	}
	if fAddr.Domain != "" {
		strAddr += "@" + fAddr.Domain
	}
	return
}

// GetOutboundDir returns outbound directory name for Points of the Node
func GetOutboundDir(fAddr FidoNetAddress) string {
	return strings.ToLower(fmt.Sprintf("%04X%04X.pnt", fAddr.Network, fAddr.Node))
}

// PktWrite creates and write .pkt file
func PktWrite(pktFileName string, pktHead PktHeader, pktPassword string, messages []FidoMessage) {

}

// PktRead returns slice of Messages from .pkt file
func PktRead(pktFileName string) (pktHead PktHeader, pktPassword string, messages []FidoMessage, err error) {
	file, err := os.Open(pktFileName)
	if err != nil {
		return
	}
	defer file.Close()

	data := readNextBytes(file, int(unsafe.Sizeof(PktHeader{})))
	buffer := bytes.NewBuffer(data)
	err = binary.Read(buffer, binary.LittleEndian, &pktHead)
	if err != nil {
		return
	}

	pktPassword = string(pktHead.Password[:8])

	for {
		data = readNextBytes(file, 2)
		if data[0] != 0x02 || data[1] != 0x00 {
			return
		}
		var pktMsg pktMsgHeader
		var msgInstance FidoMessage
		data = readNextBytes(file, int(unsafe.Sizeof(pktMsgHeader{})))
		buffer = bytes.NewBuffer(data)
		err = binary.Read(buffer, binary.LittleEndian, &pktMsg)
		if err != nil {
			return
		}
		msgInstance.ToName = string(CP866toUTF8(readNextBytesUntilZero(file, PktUserNameSize)))
		msgInstance.FromName = string(CP866toUTF8(readNextBytesUntilZero(file, PktUserNameSize)))
		msgInstance.Subj = string(CP866toUTF8(readNextBytesUntilZero(file, PktSubjectSize)))
		msgInstance.Text = string(CP866toUTF8(readNextBytesUntilZero(file, PktTextSize)))
		msgInstance.DateTime, err = time.Parse(PktDateTimeLayout, string(pktMsg.DateTime[:19]))
		if err != nil {
			return
		}
		msgInstance.FromAddr = FidoNetAddress{
			uint16(pktHead.OrigZone),
			uint16(pktMsg.OrigNet),
			uint16(pktMsg.OrigNode),
			0,
			""}
		msgInstance.ToAddr = FidoNetAddress{
			uint16(pktHead.DestZone),
			uint16(pktMsg.DestNet),
			uint16(pktMsg.DestNode),
			0,
			""}
		messages = append(messages, msgInstance)
	}
	return
}

// GetKludges returns a map of kludges (without colons) from message text (body)
func GetKludges(msgText string) map[string]string {
	kludges := make(map[string]string)
	for i, str := range strings.Split(msgText, "\n") {
		if i == 0 && strings.HasPrefix(str, "AREA:") == true {
			kl := strings.SplitN(str, ":", 2)
			kludges[kl[0]] = kl[1]
		}
		if strings.HasPrefix(str, "SEEN-BY:") == true {
			kl := strings.SplitN(str, ": ", 2)
			kludges[kl[0]] = kl[1]
		}
		if strings.HasPrefix(str, string([]byte{0x01})) == true {
			str = strings.Replace(str, "  ", " ", -1)
			kl := strings.SplitN(str, " ", 2)
			if kl[0] != "" && kl[1] != "" {
				klname := strings.TrimPrefix(kl[0], string([]byte{0x01}))
				klname = strings.TrimSuffix(klname, ":")
				kludges[klname] = kl[1]
			}
		}
	}
	return kludges
}

// GetMsgBody returns message body without kludges
func GetMsgBody(msgText string) (text string) {
	for i, str := range strings.Split(msgText, "\n") {
		if i == 0 && strings.HasPrefix(str, "AREA:") == true {
			continue
		}
		if strings.HasPrefix(str, "SEEN-BY:") == true ||
			strings.HasPrefix(str, string([]byte{0x01})) == true {
			continue
		}
		text += str + "\n"
	}
	return
}

func readNextBytes(file *os.File, len int) []byte {
	bytesGet := make([]byte, len)
	_, err := file.Read(bytesGet)
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
	return bytesGet
}

func readNextBytesUntilZero(file *os.File, len int) []byte {
	bytesGet := make([]byte, 1)
	bytesRet := make([]byte, 0)
	for i := 0; i <= len; i++ {
		_, err := file.Read(bytesGet)
		if err != nil {
			log.Fatalf("ERROR: %v", err)
		}
		if bytesGet[0] == 0x00 {
			return bytesRet
		}
		if bytesGet[0] == 0x0D {
			bytesGet[0] = 0x0A
		}
		bytesRet = append(bytesRet, bytesGet[0])
	}
	return bytesRet
}

// CP866toUTF8 converts slice of bytes from CP866 codepage to UTF8
func CP866toUTF8(src []byte) []byte {
	dec := charmap.CodePage866.NewDecoder()
	newBody := make([]byte, len(src)*2)
	n, _, err := dec.Transform(newBody, src, false)
	if err != nil {
		panic(err)
	}
	newBody = newBody[:n]
	return newBody
}

// UTF8toCP866 converts slice of bytes from UTF8 to CP866 codepage (changing russian "Н" char to similar latin "H")
func UTF8toCP866(src []byte) []byte {
	dec := charmap.CodePage866.NewEncoder()
	newBody := make([]byte, len(src))
	n, _, err := dec.Transform(newBody, src, false)
	if err != nil {
		panic(err)
	}
	newBody = bytes.Replace(newBody[:n], []byte{0x8D}, []byte{0x48}, -1)
	return newBody
}
