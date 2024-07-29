package main

import (
	"sync"

	"github.com/miekg/pkcs11"
)

type SessionPool struct {
	pool chan pkcs11.SessionHandle
	p    *pkcs11.Ctx
	slot uint
	pin  string
	mu   sync.Mutex
}

func NewSessionPool(p *pkcs11.Ctx, slot uint, pin string, size int) *SessionPool {
	sp := &SessionPool{
		pool: make(chan pkcs11.SessionHandle, size),
		p:    p,
		slot: slot,
		pin:  pin,
	}
	sp.initPool(size)
	return sp
}

func (sp *SessionPool) initPool(size int) {
	for i := 0; i < size; i++ {
		session, err := sp.p.OpenSession(sp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic(err)
		}
		if err = sp.p.Login(session, pkcs11.CKU_USER, sp.pin); err != nil {
			sp.p.CloseSession(session)
			panic(err)
		}
		sp.pool <- session
	}
}

func (sp *SessionPool) Acquire() pkcs11.SessionHandle {
	return <-sp.pool
}

func (sp *SessionPool) Release(session pkcs11.SessionHandle) {
	sp.pool <- session
}

func (sp *SessionPool) Close() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	close(sp.pool)
	for session := range sp.pool {
		sp.p.Logout(session)
		sp.p.CloseSession(session)
	}
}
