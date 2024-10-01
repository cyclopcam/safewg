package wguser

import (
	"errors"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Our message format is (little endian):
// [0:4] uint32 Message Bytes (including 8 byte header)
// [4:8] uint32 MsgType
// [8:...] Payload
// Minimum message size is 8 bytes.
// Maximum message size is 1024 * 1024 * 1024.

// We make clones of the Wireguard wgtypes structs, because we use 'gob' package to encode,
// and gob does not allow nil pointers. In addition, we want to reduce the amount of IPC
// to a minimum, and also strip things like private keys.

const MaxMsgSize = 1024 * 1024 * 1024

// const UnixSocketName = "/var/opt/kernelwg"
const UnixSocketName = "@cyclops-wg"

// Well known error messages
var ErrNotConnected = errors.New("Not connected to root wireguard process") // This is generated client-side
var ErrWireguardDeviceNotExist = errors.New("Wireguard device does not exist")

type MsgType int

const (
	MsgTypeNone MsgType = iota
	MsgTypeError
	MsgTypeAuthenticate
	MsgTypeIsDeviceAlive
	MsgTypeGetDevice
	MsgTypeGetDeviceResponse
	MsgTypeGetPeers
	MsgTypeGetPeersResponse
	MsgTypeBringDeviceUp
	MsgTypeTakeDeviceDown
	MsgTypeCreatePeersInMemory
	MsgTypeRemovePeerInMemory
	MsgTypeCreateDeviceInConfigFile
	MsgTypeSetProxyPeerInConfigFile
)

type MsgError struct {
	Error string
}

type MsgAuthenticate struct {
	Secret string
}

type MsgGetPeers struct {
	DeviceName string
}

type MsgGetDevice struct {
	DeviceName string
}

type MsgGetDeviceResponse struct {
	PrivateKey wgtypes.Key
	ListenPort int
	Addresses  []string // Unlike the other state returned here, this is read from the Wireguard config file, so it might be empty
}

type MsgGetPeersResponse struct {
	Peers []Peer
}

type MsgCreatePeersInMemory struct {
	DeviceName string
	Peers      []CreatePeerInMemory
}

type MsgRemovePeerInMemory struct {
	DeviceName string
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
}

type MsgSetProxyPeerInConfigFile struct {
	DeviceName string
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
	Endpoint   string
}

type MsgBringDeviceUp struct {
	DeviceName string
}

type MsgTakeDeviceDown struct {
	DeviceName string
}

type MsgIsDeviceAlive struct {
	DeviceName string
}

type MsgCreateDeviceInConfigFile struct {
	DeviceName string
	PrivateKey wgtypes.Key
	Addresses  []string
}

// Device is a cut-down clone of wgtypes.Device
type Device struct {
	Name       string
	ListenPort int
	Peers      []Peer
}

// Peer is a cut-down clone of wgtypes.Peer
type Peer struct {
	PublicKey                   wgtypes.Key
	PersistentKeepaliveInterval time.Duration
	LastHandshakeTime           time.Time
	ReceiveBytes                int64
	TransmitBytes               int64
	AllowedIPs                  []net.IPNet
}

type CreatePeerInMemory struct {
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
	Endpoint   string
}
