package domain

type TrafficGraph struct {
	Vertices []Vertex `json:"vertices"`
	Edges    []Edge   `json:"edges"`
}

type Vertex struct {
	Id   string `json:"id"`
	Type string `json:"type"`
}

type Edge struct {
	Source      string         `json:"source"`
	Destination string         `json:"destination"`
	Properties  EdgeProperties `json:"properties"`
}

type EdgeProperties struct {
	Weight int `json:"weight"`
	// traffic properties
	TrafficType string `json:"trafficType"`
	PacketCount int    `json:"packetCount"`
}
