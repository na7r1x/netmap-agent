package dispatchersrv

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/na7r1x/netmap-agent/internal/domain"

	"golang.org/x/net/websocket"
)

type service struct {
	origin string
	url    string
	conn   *websocket.Conn
	in     chan domain.TrafficGraphInternal
	ctx    context.Context
}

func New(origin string, url string, in chan domain.TrafficGraphInternal, ctx context.Context) *service {
	return &service{
		origin: origin,
		url:    url,
		in:     in,
		ctx:    ctx,
	}
}

func (srv *service) Connect() error {
	ws, err := websocket.Dial(srv.url, "", srv.origin)
	if err != nil {
		log.Fatal(err)
		return err
	}
	srv.conn = ws
	return nil
}

func (srv *service) Disconnect() {
	srv.conn.Close()
}

func (srv *service) Listen(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		var graph domain.TrafficGraphInternal
		select {
		case <-srv.ctx.Done():
			fmt.Println("[dispatchersrv]: received termination signal")
			return
		case graph = <-srv.in:
			srv.dispatch(srv.prepareForDispatch(graph))
		}
	}
}

func (srv *service) dispatch(payload interface{}) error {
	// fmt.Println(payload)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Sending to server...")
	if _, err := srv.conn.Write(jsonBytes); err != nil {
		log.Fatal(err)
		return err
	}
	// var msg = make([]byte, 10240)
	// var n int
	// if n, err = srv.conn.Read(msg); err != nil {
	// 	log.Fatal(err)
	// 	return err

	// }
	// fmt.Printf("Server responded with: %s.\n", msg[:n])
	return nil
}

func (srv *service) prepareForDispatch(payload domain.TrafficGraphInternal) domain.TrafficGraph {
	var _vertices []domain.Vertex
	var _edges []domain.Edge

	for k, v := range payload.Vertices {
		thisVertex := domain.Vertex{
			Id:   k,
			Type: v.Type,
		}
		_vertices = append(_vertices, thisVertex)
	}

	for k, v := range payload.Edges {
		thisEdge := domain.Edge{
			Source:      strings.Split(k, "-")[0],
			Destination: strings.Split(k, "-")[1],
			Properties:  v,
		}
		_edges = append(_edges, thisEdge)
	}

	return domain.TrafficGraph{
		Vertices:    _vertices,
		Edges:       _edges,
		PacketCount: payload.Properties.PacketCount,
		Reporter:    "placeholder",
	}

}
