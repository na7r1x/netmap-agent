package dispatchersrv

import (
	"github.com/na7r1x/netmap-agent/internal/domain"
	"log"
	"fmt"
	"encoding/json"
	"sync"
	"context"
		
	"golang.org/x/net/websocket"

)

type service struct {
	origin string
	url string
	conn *websocket.Conn
	in chan domain.TrafficGraph
	ctx context.Context
}

func New(origin string, url string, in chan domain.TrafficGraph, ctx context.Context) *service {
	return &service{
		origin: origin,
		url: url,
		in: in,
		ctx: ctx,
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
		var graph domain.TrafficGraph
		select {
		case <-srv.ctx.Done():
			fmt.Println("[dispatchersrv]: received termination signal")
			return
		case graph = <-srv.in:
			srv.dispatch(graph)
		}
	}
}

func (srv *service) dispatch(payload interface{}) error {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Sending to server...")
	if _, err := srv.conn.Write(jsonBytes); err != nil {
		log.Fatal(err)
		return err
	}
	var msg = make([]byte, 10240)
	var n int
	if n, err = srv.conn.Read(msg); err != nil {
		log.Fatal(err)
		return err

	}
	fmt.Printf("Server respnded with: %s.\n", msg[:n])
	return nil
}

