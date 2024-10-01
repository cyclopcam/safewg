package wgroot

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/cyclopcam/logs"
	"github.com/cyclopcam/safewg/wguser"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const Debug = false

type handler struct {
	log             logs.Log
	conn            net.Conn
	wg              *wgctrl.Client
	requestBuffer   bytes.Buffer
	responseBuffer  bytes.Buffer
	decoder         *gob.Decoder
	encoder         *gob.Encoder
	isAuthenticated bool
	clientSecret    string
}

func (h *handler) handleAuthenticate(request *wguser.MsgAuthenticate) error {
	if request.Secret != h.clientSecret {
		return errors.New("Invalid authentication secret")
	}
	h.isAuthenticated = true
	h.log.Infof("Authentication OK")
	return nil
}

func (h *handler) handleBringDeviceUp(request *wguser.MsgBringDeviceUp) error {
	h.log.Infof("Bring up Wireguard device %v", request.DeviceName)

	// Check first if the config file exists, so that we can return a definitive "does not exist" error.
	if _, err := os.Stat(configFilename(request.DeviceName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wguser.ErrWireguardDeviceNotExist
		}
	}

	cmd := exec.Command("wg-quick", "up", request.DeviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.log.Infof("Device %v activation failed: %v. Output: %v", request.DeviceName, err, string(output))
		return fmt.Errorf("%w: %v", err, string(output))
	}
	h.log.Infof("Device %v activation OK", request.DeviceName)
	return nil
}

func (h *handler) handleTakeDeviceDown(request *wguser.MsgTakeDeviceDown) error {
	h.log.Infof("Taking down Wireguard device %v", request.DeviceName)

	// Check first if the config file exists, so that we can return a definitive "does not exist" error.
	if _, err := os.Stat(configFilename(request.DeviceName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wguser.ErrWireguardDeviceNotExist
		}
	}

	cmd := exec.Command("wg-quick", "down", request.DeviceName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		h.log.Infof("Device %v takedown failed: %v. Output: %v", request.DeviceName, err, string(output))
		return fmt.Errorf("%w: %v", err, string(output))
	}
	h.log.Infof("Device %v is down", request.DeviceName)
	return nil
}

func (h *handler) handleIsDeviceAlive(request *wguser.MsgIsDeviceAlive) error {
	_, err := h.wg.Device(request.DeviceName)
	if errors.Is(err, os.ErrNotExist) {
		return wguser.ErrWireguardDeviceNotExist
	}
	return err
}

func (h *handler) handleGetDevice(request *wguser.MsgGetDevice) (any, error) {
	device, err := h.wg.Device(request.DeviceName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wguser.ErrWireguardDeviceNotExist
		}
		return nil, err
	}
	// This is a hack here, because we're mixing kernel-provided Wireguard state with the config file.
	// These two may be out of sync, which is why this is bad.
	// The reason I'm doing this, is because I need to know our IP address in the VPN, and I can't
	// see a cleaner way of doing this, than by looking at the Wireguard config file.
	// An alternative would be to read the output of "ip -4 address", but I've already got logic in here
	// for parsing Wireguard config files, so I'm using that.
	cfg, err := loadConfigFile(configFilename(request.DeviceName))
	addressLine := ""
	if err == nil {
		iface := cfg.findSectionByTitle("Interface")
		if iface != nil {
			a := iface.get("Address")
			if a != nil {
				addressLine = *a
			}
		}
	}

	addresses := strings.Split(addressLine, ",")
	for i := range addresses {
		addresses[i] = strings.TrimSpace(addresses[i])
	}

	resp := wguser.MsgGetDeviceResponse{
		PrivateKey: device.PrivateKey,
		ListenPort: device.ListenPort,
		Addresses:  addresses,
	}
	return &resp, nil
}

func (h *handler) handleGetPeers(request *wguser.MsgGetPeers) (any, error) {
	device, err := h.wg.Device(request.DeviceName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wguser.ErrWireguardDeviceNotExist
		}
		return nil, err
	}
	resp := wguser.MsgGetPeersResponse{}
	for _, pi := range device.Peers {
		resp.Peers = append(resp.Peers, wguser.Peer{
			PublicKey:                   pi.PublicKey,
			PersistentKeepaliveInterval: pi.PersistentKeepaliveInterval,
			LastHandshakeTime:           pi.LastHandshakeTime,
			ReceiveBytes:                pi.ReceiveBytes,
			TransmitBytes:               pi.TransmitBytes,
			AllowedIPs:                  pi.AllowedIPs,
		})
	}
	return &resp, nil
}

// Create peers in memory. They are not saved to the config file.
// This is used by the proxy for bringing peers online.
func (h *handler) handleCreatePeersInMemory(request *wguser.MsgCreatePeersInMemory) error {
	h.log.Infof("Creating %v peers", len(request.Peers))
	cfg := wgtypes.Config{
		ReplacePeers: false, // If this is false, then we append peers, which is what we want
	}
	for _, p := range request.Peers {
		//h.log.Infof("Peer %v, %v, (%v)", p.AllowedIP.IP, p.AllowedIP.Mask, p.AllowedIP)
		cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AllowedIPs,
		})
	}
	if err := h.wg.ConfigureDevice(request.DeviceName, cfg); err != nil {
		return err
	}

	// Create IP routes
	for _, p := range request.Peers {
		var cmd *exec.Cmd
		for _, ipnet := range p.AllowedIPs {
			if ipnet.IP.To4() != nil {
				// ip -4 route add 10.100.1.1/32 dev cyclops
				h.log.Infof("Creating IPv4 route to %v", ipnet.String())
				cmd = exec.Command("ip", "-4", "route", "add", ipnet.String(), "dev", request.DeviceName)
			} else {
				// ip -6 route add 2001:db8:1::1/128 dev cyclops
				h.log.Infof("Creating IPv6 route to %v", ipnet.String())
				cmd = exec.Command("ip", "-6", "route", "add", ipnet.String(), "dev", request.DeviceName)
			}
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("Error creating IP route to %v: %w", ipnet.String(), err)
			}
		}
	}

	return nil
}

func (h *handler) handleRemovePeerInMemory(request *wguser.MsgRemovePeerInMemory) error {
	h.log.Infof("Removing peer %v", request.PublicKey)
	cfg := wgtypes.Config{}
	cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
		PublicKey: request.PublicKey,
		Remove:    true,
	})
	if err := h.wg.ConfigureDevice(request.DeviceName, cfg); err != nil {
		return err
	}

	// Delete IP routes
	for _, ipnet := range request.AllowedIPs {
		var cmd *exec.Cmd
		if ipnet.IP.To4() != nil {
			// ip -4 route delete 10.101.1.2/32 dev cyclops
			cmd = exec.Command("ip", "-4", "route", "delete", ipnet.String(), "dev", request.DeviceName)
		} else {
			// ip -6 route delete 2001:db8:1::2/128 dev cyclops
			cmd = exec.Command("ip", "-6", "route", "delete", ipnet.String(), "dev", request.DeviceName)
		}
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("Error deleting IP route to %v: %w", ipnet.String(), err)
		}
	}

	return nil
}

func configFilename(deviceName string) string {
	return fmt.Sprintf("/etc/wireguard/%v.conf", deviceName)
}

// This is used on a Cyclops server when it is setting up it's Wireguard interface to
// the proxy server. The purpose of this function is to create the initial /etc/wireguard/cyclops.conf
// file, and/or set the [Interface] section at the top of that file.
func (h *handler) handleCreateDeviceInConfigFile(request *wguser.MsgCreateDeviceInConfigFile) error {
	h.log.Infof("Creating %v", configFilename(request.DeviceName))
	cfg, err := loadConfigFile(configFilename(request.DeviceName))
	if errors.Is(err, os.ErrNotExist) {
		cfg = &configFile{}
	} else if err != nil {
		return err
	}

	iface := cfg.findSectionByTitle("Interface")
	if iface == nil {
		iface = cfg.addSection("Interface")
	}

	iface.set("PrivateKey", request.PrivateKey.String())
	iface.set("Address", strings.Join(request.Addresses, ", "))

	return cfg.writeFile(configFilename(request.DeviceName))
}

// This is used on a Cyclops server when it is setting up it's Wireguard interface to
// the proxy server. The purpose of this function is to add the [Peer] section to
// /etc/wireguard/cyclops.conf that points to our proxy server.
func (h *handler) handleSetProxyPeerInConfigFile(request *wguser.MsgSetProxyPeerInConfigFile) error {
	h.log.Infof("Setting proxy peer in cyclops.conf")
	cfg, err := loadConfigFile(configFilename(request.DeviceName))
	if err != nil {
		return err
	}

	peer := cfg.findSectionByKeyValue("Peer", "PublicKey", request.PublicKey.String())
	if peer == nil {
		peer = cfg.addSection("Peer")
	}

	allowedIPs := []string{}
	for _, ipnet := range request.AllowedIPs {
		allowedIPs = append(allowedIPs, ipnet.String())
	}

	peer.set("PublicKey", request.PublicKey.String())
	peer.set("Endpoint", request.Endpoint)
	peer.set("AllowedIPs", strings.Join(allowedIPs, ", "))
	peer.set("PersistentKeepalive", "25")

	return cfg.writeFile(configFilename(request.DeviceName))
}

func (h *handler) handleMessage(msgType wguser.MsgType, msgLen int) error {
	if Debug {
		h.log.Infof("handleMessage %v, %v bytes", msgType, msgLen)
	}

	// Decode request body

	// NOTE: There is another switch statement a few lines down, which also needs
	// to handle all message types.
	var request any
	switch msgType {
	case wguser.MsgTypeAuthenticate:
		request = &wguser.MsgAuthenticate{}
	case wguser.MsgTypeGetPeers:
		request = &wguser.MsgGetPeers{}
	case wguser.MsgTypeGetDevice:
		request = &wguser.MsgGetDevice{}
	case wguser.MsgTypeCreatePeersInMemory:
		request = &wguser.MsgCreatePeersInMemory{}
	case wguser.MsgTypeRemovePeerInMemory:
		request = &wguser.MsgRemovePeerInMemory{}
	case wguser.MsgTypeCreateDeviceInConfigFile:
		request = &wguser.MsgCreateDeviceInConfigFile{}
	case wguser.MsgTypeSetProxyPeerInConfigFile:
		request = &wguser.MsgSetProxyPeerInConfigFile{}
	case wguser.MsgTypeBringDeviceUp:
		request = &wguser.MsgBringDeviceUp{}
	case wguser.MsgTypeTakeDeviceDown:
		request = &wguser.MsgTakeDeviceDown{}
	case wguser.MsgTypeIsDeviceAlive:
		request = &wguser.MsgIsDeviceAlive{}
	}
	if request != nil {
		err := h.decoder.Decode(request)
		if err != nil {
			h.log.Errorf("Error decoding request: %v", err)
			return fmt.Errorf("Error decoding request: %w", err)
		}
	}

	respType := wguser.MsgTypeNone
	var resp any
	var err error

	if !h.isAuthenticated && msgType != wguser.MsgTypeAuthenticate {
		err = errors.New("Not authenticated")
	} else {
		// NOTE: There is another switch statement a few lines above, which also needs
		// to handle all message types.
		switch msgType {
		case wguser.MsgTypeAuthenticate:
			err = h.handleAuthenticate(request.(*wguser.MsgAuthenticate))
		case wguser.MsgTypeGetPeers:
			respType = wguser.MsgTypeGetPeersResponse
			resp, err = h.handleGetPeers(request.(*wguser.MsgGetPeers))
		case wguser.MsgTypeGetDevice:
			respType = wguser.MsgTypeGetDeviceResponse
			resp, err = h.handleGetDevice(request.(*wguser.MsgGetDevice))
		case wguser.MsgTypeCreatePeersInMemory:
			err = h.handleCreatePeersInMemory(request.(*wguser.MsgCreatePeersInMemory))
		case wguser.MsgTypeRemovePeerInMemory:
			err = h.handleRemovePeerInMemory(request.(*wguser.MsgRemovePeerInMemory))
		case wguser.MsgTypeCreateDeviceInConfigFile:
			err = h.handleCreateDeviceInConfigFile(request.(*wguser.MsgCreateDeviceInConfigFile))
		case wguser.MsgTypeSetProxyPeerInConfigFile:
			err = h.handleSetProxyPeerInConfigFile(request.(*wguser.MsgSetProxyPeerInConfigFile))
		case wguser.MsgTypeBringDeviceUp:
			err = h.handleBringDeviceUp(request.(*wguser.MsgBringDeviceUp))
		case wguser.MsgTypeTakeDeviceDown:
			err = h.handleTakeDeviceDown(request.(*wguser.MsgTakeDeviceDown))
		case wguser.MsgTypeIsDeviceAlive:
			err = h.handleIsDeviceAlive(request.(*wguser.MsgIsDeviceAlive))
		default:
			err = fmt.Errorf("Invalid request message %v", int(msgType))
		}
	}
	if err != nil {
		// Send error response
		respType = wguser.MsgTypeError
		resp = &wguser.MsgError{Error: err.Error()}
		err = nil
	}

	headerPlaceholder := [8]byte{}

	h.responseBuffer.Reset()
	h.responseBuffer.Write(headerPlaceholder[:])
	if resp != nil {
		if respType == wguser.MsgTypeNone {
			panic("Response type not populated")
		}
		if err := h.encoder.Encode(resp); err != nil {
			return fmt.Errorf("Response encoding failed: %v", err)
		}
	}
	if h.responseBuffer.Len() > wguser.MaxMsgSize {
		// Send an error response
		h.log.Errorf("Response too large (%v bytes)", h.responseBuffer.Len())
		h.responseBuffer.Reset()
		h.responseBuffer.Write(headerPlaceholder[:])
		respType = wguser.MsgTypeError
		if err := h.encoder.Encode(&wguser.MsgError{Error: "Response too large"}); err != nil {
			// This is not expected
			return fmt.Errorf("Double fault: %v", err)
		}
	}
	header := h.responseBuffer.Bytes()
	binary.LittleEndian.PutUint32(header[0:4], uint32(h.responseBuffer.Len()))
	binary.LittleEndian.PutUint32(header[4:8], uint32(respType))
	_, err = io.Copy(h.conn, &h.responseBuffer)
	if err != nil {
		return fmt.Errorf("Response sending failed: %v", err)
	}
	return nil
}

func handleConnection(conn net.Conn, log logs.Log, clientSecret string) {
	wg, err := wgctrl.New()
	if err != nil {
		log.Errorf("Error creating wgctrl: %v", err)
		return
	}
	defer wg.Close()

	h := &handler{
		conn:         conn,
		log:          log,
		wg:           wg,
		clientSecret: clientSecret,
	}
	h.encoder = gob.NewEncoder(&h.responseBuffer)
	h.decoder = gob.NewDecoder(&h.requestBuffer)
	buf := [4096]byte{}
	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			log.Errorf("conn.Read failed: %v", err)
			return
		}
		if Debug {
			log.Infof("Read %v bytes", n)
		}
		h.requestBuffer.Write(buf[:n])
		if h.requestBuffer.Len() >= 8 {
			// This little chunk of code will run over and over until len(raw) == expectedRawLen
			req := h.requestBuffer.Bytes()
			msgLen := int(binary.LittleEndian.Uint32(req[:4]))
			if msgLen > wguser.MaxMsgSize {
				log.Errorf("Request payload is too large (%v bytes)", msgLen)
				return
			}
			msgType := wguser.MsgType(binary.LittleEndian.Uint32(req[4:8]))
			if h.requestBuffer.Len() > msgLen {
				log.Errorf("Request is larger than specified (%v > %v)", h.requestBuffer.Len(), msgLen)
				return
			}
			if h.requestBuffer.Len() == msgLen {
				// consume our header, so that the GOB decoder can see only it's data
				dump := [8]byte{}
				h.requestBuffer.Read(dump[:])

				err = h.handleMessage(msgType, msgLen)
				if err != nil {
					return
				}
				h.requestBuffer.Reset()
			}
		}
	}
}

func verifyPermissions(logger logs.Log) error {
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("Error creating wgctrl: %w", err)
	}
	defer wg.Close()

	// Sanity check
	//device, err := wg.Device("cyclops")
	//if err != nil {
	//	return fmt.Errorf("Error scanning Wireguard device: %v", err)
	//}
	//logger.Infof("Wireguard device public key: %v", device.PublicKey)

	devices, err := wg.Devices()
	if err != nil {
		return fmt.Errorf("Error scanning Wireguard devices: %v", err)
	}
	logger.Infof("Found %v active wireguard devices", len(devices))
	for _, d := range devices {
		logger.Infof("Wireguard device %v public key: %v", d.Name, d.PublicKey)
	}

	return nil
}

func Main() {
	logger, err := logs.NewLog()
	if err != nil {
		panic(err)
	}
	logger = logs.NewPrefixLogger(logger, "kernelwg")

	clientSecret := os.Getenv("CYCLOPS_SOCKET_SECRET")
	if clientSecret == "" {
		logger.Criticalf("CYCLOPS_SOCKET_SECRET environment variable not set")
		os.Exit(1)
	}

	logger.Infof("Verifying if we can inspect wireguard devices")

	if err := verifyPermissions(logger); err != nil {
		logger.Criticalf("%v", err)
		panic(err)
	}
	logger.Infof("Wireguard communication successful")

	//listenAddr := "127.0.0.1:666"
	listenAddr := net.UnixAddr{
		Net:  "unix",
		Name: wguser.UnixSocketName,
	}

	logger.Infof("Listening on %v", listenAddr)
	ln, err := net.ListenUnix("unix", &listenAddr)
	//ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger.Errorf("Error listening: %v", err)
		os.Exit(1)
	}

	// Tell systemd that we're alive, so that the cyclops service can start up
	// (no longer necessary since all functionality has been integrated into a single executable,
	//  with two different 'main' functions)
	//daemon.SdNotify(false, daemon.SdNotifyReady)

	ln.SetUnlinkOnClose(true)

	// Only connect to a single socket at a time, and when it disconnects, we die
	conn, err := ln.Accept()
	if err != nil {
		logger.Errorf("Error accepting connection: %v", err)
	}
	logger.Infof("Accept connection from %v", conn.RemoteAddr().String())

	// Note that we do not do "go handleConnection", because our design is to be used by a single
	// client, in half-duplex mode (i.e. synchronous request/response).
	handleConnection(conn, logger, clientSecret)

	logger.Infof("Exiting")
}
