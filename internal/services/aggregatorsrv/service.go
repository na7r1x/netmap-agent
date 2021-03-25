package aggregatorsrv

import (
	"fmt"

	"github.com/na7r1x/netmap-agent/internal/domain"
)

type service struct {
	in    chan domain.PacketEnvelope
	out   chan domain.TrafficGraph
	stop  chan struct{}
	flush chan bool
	graph domain.TrafficGraph
}

func New(in chan domain.PacketEnvelope, out chan domain.TrafficGraph, stop chan struct{}) *service {
	return &service{
		in:    in,
		out:   out,
		stop:  stop,
		graph: domain.TrafficGraph{},
		flush: make(chan bool),
	}
}

func (srv *service) Listen() {
	for {
		var packet domain.PacketEnvelope
		select {
		case <-srv.stop:
			return
		case packet = <-srv.in:
			srv.aggregate(packet)
		case <-srv.flush:
			fmt.Println("not implemented: send graph off to bastion")
		}
	}
}

func (srv *service) Flush() {
	srv.flush <- true
}

func (srv *service) aggregate(p domain.PacketEnvelope) {
	fmt.Println("not implemented: aggregate packet envelope to the traffic graph")
}
