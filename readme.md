# Safe Wireguard Interface

`safewg` is a pair of Go packages for controlling Wireguard from a process that
doesn't have root priviledges.

The way to use is it that your process initially starts with root priviledges,
then you spawn the Wireguard controller (with root priviledges), and then you
spawn a copy of yourself with reduced priviledges.

The reduced-priviledge process connects to the priviledged process via a unix
socket, and they communicate using a simple protocol built around Go's GOB
encoder/decoder.
