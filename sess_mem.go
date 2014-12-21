// Copyright 2013 Beego Authors
// Copyright 2014 Unknwon
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package session

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// MemSessionStore represents a in-memory session store implementation.
type MemSessionStore struct {
	sid        string
	lock       sync.RWMutex
	data       map[interface{}]interface{}
	lastAccess time.Time
}

// NewMemSessionStore creates and returns a memory session store.
func NewMemSessionStore(sid string) *MemSessionStore {
	return &MemSessionStore{
		sid:        sid,
		data:       make(map[interface{}]interface{}),
		lastAccess: time.Now(),
	}
}

// Set sets value to given key in session.
func (s *MemSessionStore) Set(key, val interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data[key] = val
	return nil
}

// Get gets value by given key in session.
func (s *MemSessionStore) Get(key interface{}) interface{} {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data[key]
}

// Delete delete a key from session.
func (s *MemSessionStore) Delete(key interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.data, key)
	return nil
}

// SessionID returns current session ID.
func (s *MemSessionStore) SessionID() string {
	return s.sid
}

// SessionRelease releases resource and save data to provider.
func (_ *MemSessionStore) SessionRelease(_ http.ResponseWriter) {
	// Nothing to do with memory.
}

// Flush deletes all session data.
func (s *MemSessionStore) Flush() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = make(map[interface{}]interface{})
	return nil
}

// MemProvider represents a in-memory session provider implementation.
type MemProvider struct {
	lock        sync.RWMutex
	maxLifetime int64
	data        map[string]*list.Element
	// A priority list whose lastAccess newer gets higer priority.
	list *list.List
}

// SessionInit initializes memory session provider.
func (p *MemProvider) SessionInit(maxLifetime int64, _ string) error {
	p.maxLifetime = maxLifetime
	return nil
}

// SessionUpdate expands time of session store by given ID.
func (p *MemProvider) SessionUpdate(sid string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if e, ok := p.data[sid]; ok {
		e.Value.(*MemSessionStore).lastAccess = time.Now()
		p.list.MoveToFront(e)
		return nil
	}
	return nil
}

// SessionRead returns raw session store by session ID.
func (p *MemProvider) SessionRead(sid string) (_ RawStore, err error) {
	p.lock.RLock()
	e, ok := p.data[sid]
	p.lock.RUnlock()

	if ok {
		if err = p.SessionUpdate(sid); err != nil {
			return nil, err
		}
		return e.Value.(*MemSessionStore), nil
	}

	// Create a new session.
	p.lock.Lock()
	defer p.lock.Unlock()

	sess := NewMemSessionStore(sid)
	e = p.list.PushBack(sess)
	p.data[sid] = e
	return sess, nil
}

// SessionExist returns true if session with given ID exists.
func (p *MemProvider) SessionExist(sid string) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	_, ok := p.data[sid]
	return ok
}

// SessionRegenerate regenerates a session store from old session ID to new one.
func (pder *MemProvider) SessionRegenerate(oldsid, sid string) (RawStore, error) {
	pder.lock.RLock()
	if element, ok := pder.data[oldsid]; ok {
		go pder.SessionUpdate(oldsid)
		pder.lock.RUnlock()
		pder.lock.Lock()
		element.Value.(*MemSessionStore).sid = sid
		pder.data[sid] = element
		delete(pder.data, oldsid)
		pder.lock.Unlock()
		return element.Value.(*MemSessionStore), nil
	} else {
		pder.lock.RUnlock()
		pder.lock.Lock()
		newsess := &MemSessionStore{sid: sid, lastAccess: time.Now(), data: make(map[interface{}]interface{})}
		element := pder.list.PushBack(newsess)
		pder.data[sid] = element
		pder.lock.Unlock()
		return newsess, nil
	}
}

// SessionDestroy deletes a session by session ID.
func (p *MemProvider) SessionDestroy(sid string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	e, ok := p.data[sid]
	if !ok {
		return nil
	}

	p.list.Remove(e)
	delete(p.data, sid)
	return nil
}

// SessionAll returns number of active sessions.
func (p *MemProvider) SessionAll() int {
	return p.list.Len()
}

// SessionGC calls GC to clean expired sessions.
func (p *MemProvider) SessionGC() {
	p.lock.RLock()
	for {
		// No session in the list.
		e := p.list.Back()
		if e == nil {
			break
		}

		if (e.Value.(*MemSessionStore).lastAccess.Unix() + p.maxLifetime) < time.Now().Unix() {
			p.lock.RUnlock()
			p.lock.Lock()
			p.list.Remove(e)
			delete(p.data, e.Value.(*MemSessionStore).sid)
			p.lock.Unlock()
			p.lock.RLock()
		} else {
			break
		}
	}
	p.lock.RUnlock()
}

func init() {
	Register("memory", &MemProvider{list: list.New(), data: make(map[string]*list.Element)})
}
