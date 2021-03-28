package domain

type TrafficGraphInternal struct {
	Vertices   map[string]VertexProperties `json:"vertices"`
	Edges      map[string]EdgeProperties   `json:"edges"`
	Properties TrafficGraphProperties      `json:"properties"`
}

type TrafficGraph struct {
	Vertices    []Vertex `json:"vertices"`
	Edges       []Edge   `json:"edges"`
	PacketCount int      `json:"packetCount"`
	Reporter    string   `json:"reporter"`
}

type TrafficGraphProperties struct {
	PacketCount int `json:"packetCount"`
}

type Vertex struct {
	Id   string `json:"id"`
	Type string `json:"type"`
}

type VertexProperties struct {
	Type string `json:"type"`
}

type Edge struct {
	Source      string         `json:"source"`
	Destination string         `json:"destination"`
	Properties  EdgeProperties `json:"properties"`
}

type EdgeProperties struct {
	Weight float32 `json:"weight"`
	// traffic properties
	TrafficType string `json:"trafficType"`
	PacketCount int    `json:"packetCount"`
	// direction
	SourcePort      int `json:"sourcePort"`
	DestinationPort int `json:"destinationPort"`
}
