package aggregatorsrv

import (
	"context"
	"fmt"
	"sync"

	"github.com/na7r1x/netmap-agent/internal/domain"
)

type service struct {
	in    chan domain.PacketEnvelope
	out   chan domain.TrafficGraph
	ctx   context.Context
	flush chan bool
	graph domain.TrafficGraph
}

func New(in chan domain.PacketEnvelope, out chan domain.TrafficGraph, ctx context.Context) *service {
	return &service{
		in:  in,
		out: out,
		ctx: ctx,
		graph: domain.TrafficGraph{
			Vertices: make(map[string]domain.VertexProperties),
			Edges:    make(map[string]domain.EdgeProperties),
			Properties: domain.TrafficGraphProperties{
				PacketCount: 0,
			},
		},
		flush: make(chan bool),
	}
}

func (srv *service) Listen(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		var packet domain.PacketEnvelope
		select {
		case <-srv.ctx.Done():
			fmt.Println("[aggregatorsrv]: received termination signal")
			return
		case packet = <-srv.in:
			srv.aggregate(packet)
		case <-srv.flush:
			fmt.Println("Flushing graph...")
			if srv.graph.Properties.PacketCount == 0 {
				fmt.Println("Nothing to flush.")
			}
			srv.out <- srv.graph
			srv.emptyGraph()
		}
	}
}

func (srv *service) Flush() {
	srv.flush <- true
}

func (srv *service) aggregate(p domain.PacketEnvelope) {
	// increment packet count
	srv.graph.Properties.PacketCount++

	// check source vertex exists
	// srcVertex := domain.Vertex{
	// 	Id: p.SrcAddr,
	// }
	srcVertex := p.SrcAddr
	if _, ok := srv.graph.Vertices[srcVertex]; !ok {
		srv.graph.Vertices[srcVertex] = domain.VertexProperties{
			Type: "host",
		}
	}

	// check destination vertex exists
	// dstVertex := domain.Vertex{
	// 	Id: p.DstAddr,
	// }
	dstVertex := p.DstAddr
	if _, ok := srv.graph.Vertices[dstVertex]; !ok {
		srv.graph.Vertices[dstVertex] = domain.VertexProperties{
			Type: "host",
		}
	}

	// upsert edge
	// edge := domain.Edge{
	// 	Source:      srcVertex,
	// 	Destination: dstVertex,
	// }
	edge := p.SrcAddr + "-" + p.DstAddr
	if e, ok := srv.graph.Edges[edge]; ok {
		e.PacketCount++
		e.Weight = float32(e.PacketCount) / float32(srv.graph.Properties.PacketCount)
		srv.graph.Edges[edge] = e
	} else {
		// if not exist, create it
		srv.graph.Edges[edge] = domain.EdgeProperties{
			Weight:          float32(1 / srv.graph.Properties.PacketCount),
			TrafficType:     p.Type,
			PacketCount:     1,
			SourcePort:      p.SrcPort,
			DestinationPort: p.DstPort,
		}
	}

	// adjust edge weights
	for k, v := range srv.graph.Edges {
		v.Weight = float32(v.PacketCount) / float32(srv.graph.Properties.PacketCount)
		srv.graph.Edges[k] = v
	}
}

func (srv *service) emptyGraph() {
	srv.graph = domain.TrafficGraph{
		Vertices: make(map[string]domain.VertexProperties),
		Edges:    make(map[string]domain.EdgeProperties),
		Properties: domain.TrafficGraphProperties{
			PacketCount: 0,
		},
	}
}
