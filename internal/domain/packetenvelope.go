package domain

type PacketEnvelope struct {
	Type    string
	SrcAddr string
	SrcPort int
	DstAddr string
	DstPort int
}
