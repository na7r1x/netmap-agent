package domain

type TrafficGraph struct {
	Vertices   map[string]VertexProperties `json:"vertices"`
	Edges      map[string]EdgeProperties `json:"edges"`
	Properties TrafficGraphProperties `json:"properties"`
}

type TrafficGraphProperties struct {
	PacketCount int `json:"packetCount"`
}

type Vertex struct {
	Id string `json:"id"`
}

type VertexProperties struct {
	Type string `json:"type"`
}

type Edge struct {
	Source      Vertex `json:"source"`
	Destination Vertex `json:"destination"`
}

type EdgeProperties struct {
	Weight float32 `json:"weight"`
	// traffic properties
	TrafficType string `json:"trafficType"`
	PacketCount int    `json:"packetCount"`
	// direction
	SourcePort      int `json:"sourcePort`
	DestinationPort int `json:"destinationPort"`
}
