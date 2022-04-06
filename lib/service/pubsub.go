package service

import (
	"sync"

	"github.com/getAlby/lndhub.go/db/models"
)

type Pubsub struct {
	mu   sync.RWMutex
	subs map[int64]map[string]chan models.Invoice
}

func NewPubsub() *Pubsub {
	ps := &Pubsub{}
	ps.subs = make(map[int64]map[string]chan models.Invoice)
	return ps
}

func (ps *Pubsub) Subscribe(id string, topic int64, ch chan models.Invoice) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.subs[topic][id] = ch
}

func (ps *Pubsub) Unsubscribe(id string, topic int64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.subs[topic], id)
}

func (ps *Pubsub) Publish(topic int64, msg models.Invoice) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	for _, ch := range ps.subs[topic] {
		ch <- msg
	}
}

func (ps *Pubsub) CloseAll() {
	for _, subs := range ps.subs {
		for _, ch := range subs {
			close(ch)
		}
	}
}
