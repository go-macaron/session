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

// Package session a middleware that provides the session manager of Macaron.
package session

// NOTE: last sync 000033e on Nov 4, 2014.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Unknwon/macaron"
)

const _VERSION = "0.0.6"

func Version() string {
	return _VERSION
}

// RawStore is the interface that operates the session data.
type RawStore interface {
	// Set sets value to given key in session.
	Set(key, value interface{}) error
	// Get gets value by given key in session.
	Get(key interface{}) interface{}
	// Delete delete a key from session.
	Delete(key interface{}) error
	// SessionID returns current session ID.
	SessionID() string
	// SessionRelease releases resource and save data to provider.
	SessionRelease(w http.ResponseWriter)
	// Flush deletes all session data.
	Flush() error
}

// Store is the interface that contains all data for one session process with specific ID.
type Store interface {
	RawStore
	// GetSessionStore returns raw session store by session ID.
	GetSessionStore(string) (RawStore, error)
	// Destory deletes a session by session ID.
	Destory(string) error
	// GetActiveSession returns number of active sessions.
	GetActiveSession() int
	// GC calls GC to clean expired sessions.
	GC()
}

type store struct {
	RawStore
	*Manager
}

// Config represents session provider configuration.
type Config struct {
	CookieName      string `json:"cookieName"`
	CookiePath      string `json:"cookiePath"`
	EnableSetCookie bool   `json:"enableSetCookie,omitempty"`
	Gclifetime      int64  `json:"gclifetime"`
	Maxlifetime     int64  `json:"maxLifetime"`
	Secure          bool   `json:"secure"`
	CookieLifeTime  int    `json:"cookieLifeTime"`
	ProviderConfig  string `json:"providerConfig"`
	Domain          string `json:"domain"`
	SessionIDLength int64  `json:"sessionIdLength"`
}

// Options represents a struct for specifying configuration options for the session middleware.
type Options struct {
	// Name of provider. Default is memory.
	Provider string
	// Provider configuration.
	Config
}

func prepareOptions(options []Options) Options {
	var opt Options
	if len(options) > 0 {
		opt = options[0]
	}

	// Defaults.
	if len(opt.Provider) == 0 {
		opt.Provider = "memory"
	}
	opt.EnableSetCookie = true
	if len(opt.CookieName) == 0 {
		opt.CookieName = "MacaronSession"
	}
	if len(opt.CookiePath) == 0 {
		opt.CookiePath = "/"
	}
	if opt.Gclifetime == 0 {
		opt.Gclifetime = 3600
	}
	if opt.Maxlifetime == 0 {
		opt.Maxlifetime = opt.Gclifetime
	}
	if opt.SessionIDLength == 0 {
		opt.SessionIDLength = 16
	}

	return opt
}

// Sessioner is a middleware that maps a session.SessionStore service into the Macaron handler chain.
// An single variadic session.Options struct can be optionally provided to configure.
func Sessioner(options ...Options) macaron.Handler {
	opt := prepareOptions(options)
	manager, err := NewManager(opt.Provider, &opt.Config)
	if err != nil {
		panic(err)
	}
	go manager.GC()

	return func(ctx *macaron.Context) {
		// FIXME: should I panic for error?
		sess, _ := manager.SessionStart(ctx)

		// Get flash.
		vals, _ := url.ParseQuery(ctx.GetCookie("macaron_flash"))
		if len(vals) > 0 {
			f := &Flash{Values: vals}
			f.ErrorMsg = f.Get("error")
			f.SuccessMsg = f.Get("success")
			f.InfoMsg = f.Get("info")
			f.WarningMsg = f.Get("warning")
			ctx.Data["Flash"] = f
			ctx.SetCookie("macaron_flash", "", -1, opt.CookiePath)
		}

		f := &Flash{ctx, url.Values{}, "", "", "", ""}
		ctx.Resp.Before(func(macaron.ResponseWriter) {
			if flash := f.Encode(); len(flash) > 0 {
				ctx.SetCookie("macaron_flash", flash, 0, opt.CookiePath)
			}
		})

		ctx.Map(f)
		s := store{
			RawStore: sess,
			Manager:  manager,
		}
		ctx.MapTo(s, (*Store)(nil))

		ctx.Next()

		sess.SessionRelease(ctx.Resp)
	}
}

// Provider is the interface that provides session manipulations.
type Provider interface {
	// SessionInit initializes session provider.
	SessionInit(gclifetime int64, config string) error
	// SessionRead returns raw session store by session ID.
	SessionRead(sid string) (RawStore, error)
	// SessionExist returns true if session with given ID exists.
	SessionExist(sid string) bool
	// SessionRegenerate regenerates a session store from old session ID to new one.
	SessionRegenerate(oldsid, sid string) (RawStore, error)
	// SessionDestroy deletes a session by session ID.
	SessionDestroy(sid string) error
	// SessionAll returns number of active sessions.
	SessionAll() int
	// SessionGC calls GC to clean expired sessions.
	SessionGC()
}

var providers = make(map[string]Provider)

// Register registers a provider.
func Register(name string, provider Provider) {
	if provider == nil {
		panic("session: cannot register provider with nil value")
	}
	if _, dup := providers[name]; dup {
		panic(fmt.Errorf("session: cannot register provider '%s' twice", name))
	}
	providers[name] = provider
}

//    _____
//   /     \ _____    ____ _____     ____   ___________
//  /  \ /  \\__  \  /    \\__  \   / ___\_/ __ \_  __ \
// /    Y    \/ __ \|   |  \/ __ \_/ /_/  >  ___/|  | \/
// \____|__  (____  /___|  (____  /\___  / \___  >__|
//         \/     \/     \/     \//_____/      \/

// Manager represents a struct that contains session provider and its configuration.
type Manager struct {
	provider Provider
	config   *Config
}

// NewManager creates and returns a new session manager by given provider name and configuration.
// It panics when given provider isn't registered.
func NewManager(name string, cfg *Config) (*Manager, error) {
	p, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("session: unknown provider ‘%q’(forgotten import?)", name)
	}
	if err := p.SessionInit(cfg.Maxlifetime, cfg.ProviderConfig); err != nil {
		return nil, err
	}
	return &Manager{p, cfg}, nil
}

// sessionId generates a new session ID with rand string, unix nano time, remote addr by hash function.
func (m *Manager) sessionId() (string, error) {
	k := make([]byte, m.config.SessionIDLength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return "", fmt.Errorf("error generating random string: %v", err)
	}
	return hex.EncodeToString(k), nil
}

// SessionStart starts a session by generating new one
// or retrieve existence one by reading session ID from HTTP request if it's valid.
func (m *Manager) SessionStart(ctx *macaron.Context) (RawStore, error) {
	sid := ctx.GetCookie(m.config.CookieName)
	if len(sid) > 0 && m.provider.SessionExist(sid) {
		return m.provider.SessionRead(sid)
	}

	sid, err := m.sessionId()
	if err != nil {
		return nil, err
	}
	sess, err := m.provider.SessionRead(sid)
	if err != nil {
		return nil, err
	}

	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Value:    url.QueryEscape(sid),
		Path:     m.config.CookiePath,
		HttpOnly: true,
		Secure:   m.config.Secure,
		Domain:   m.config.Domain,
	}
	if m.config.CookieLifeTime >= 0 {
		cookie.MaxAge = m.config.CookieLifeTime
	}
	if m.config.EnableSetCookie {
		http.SetCookie(ctx.Resp, cookie)
	}
	ctx.Req.AddCookie(cookie)
	return sess, nil
}

// GC starts GC job in a certain period.
func (m *Manager) GC() {
	m.provider.SessionGC()
	time.AfterFunc(time.Duration(m.config.Gclifetime)*time.Second, func() { m.GC() })
}

// SessionDestroy deletes a session by given ID.
func (m *Manager) SessionDestroy(ctx *macaron.Context) error {
	sid := ctx.GetCookie(m.config.CookieName)
	if len(sid) == 0 {
		return nil
	}

	if err := m.provider.SessionDestroy(sid); err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     m.config.CookieName,
		Path:     m.config.CookiePath,
		HttpOnly: true,
		Expires:  time.Now(),
		MaxAge:   -1,
	}
	http.SetCookie(ctx.Resp, cookie)
	return nil
}

// GetSessionStore returns raw session store by session ID.
func (m *Manager) GetSessionStore(sid string) (RawStore, error) {
	return m.provider.SessionRead(sid)
}

// Destory deletes a session by session ID.
func (m *Manager) Destory(sid string) error {
	return m.provider.SessionDestroy(sid)
}

// GetActiveSession returns number of active sessions.
func (m *Manager) GetActiveSession() int {
	return m.provider.SessionAll()
}

// SessionRegenerate regenerates a session store from old session ID to new one.
func (m *Manager) SessionRegenerateId(w http.ResponseWriter, r *http.Request) (session RawStore) {
	sid, err := m.sessionId()
	if err != nil {
		return nil
	}

	cookie, err := r.Cookie(m.config.CookieName)
	if err != nil && cookie.Value == "" {
		session, err = m.provider.SessionRead(sid)
		if err != nil {
			return nil
		}
		cookie = &http.Cookie{Name: m.config.CookieName,
			Value:    url.QueryEscape(sid),
			Path:     m.config.CookiePath,
			HttpOnly: true,
			Secure:   m.config.Secure,
			Domain:   m.config.Domain,
		}
	} else {
		oldsid, err := url.QueryUnescape(cookie.Value)
		if err != nil {
			return nil
		}
		session, err = m.provider.SessionRegenerate(oldsid, sid)
		if err != nil {
			return nil
		}
		cookie.Value = url.QueryEscape(sid)
		cookie.HttpOnly = true
		cookie.Path = "/"
	}
	if m.config.CookieLifeTime >= 0 {
		cookie.MaxAge = m.config.CookieLifeTime
	}
	http.SetCookie(w, cookie)
	r.AddCookie(cookie)
	return session
}

// SetSecure indicates whether to set cookie with HTTPS or not.
func (m *Manager) SetSecure(secure bool) {
	m.config.Secure = secure
}

// ___________.____       _____    _________ ___ ___
// \_   _____/|    |     /  _  \  /   _____//   |   \
//  |    __)  |    |    /  /_\  \ \_____  \/    ~    \
//  |     \   |    |___/    |    \/        \    Y    /
//  \___  /   |_______ \____|__  /_______  /\___|_  /
//      \/            \/       \/        \/       \/

type Flash struct {
	ctx *macaron.Context
	url.Values
	ErrorMsg, WarningMsg, InfoMsg, SuccessMsg string
}

func (f *Flash) set(name, msg string, current ...bool) {
	isShow := false
	if (len(current) == 0 && macaron.FlashNow) ||
		(len(current) > 0 && current[0]) {
		isShow = true
	}

	if isShow {
		f.ctx.Data["Flash"] = f
	} else {
		f.Set(name, msg)
	}
}

func (f *Flash) Error(msg string, current ...bool) {
	f.ErrorMsg = msg
	f.set("error", msg, current...)
}

func (f *Flash) Warning(msg string, current ...bool) {
	f.WarningMsg = msg
	f.set("warning", msg, current...)
}

func (f *Flash) Info(msg string, current ...bool) {
	f.InfoMsg = msg
	f.set("info", msg, current...)
}

func (f *Flash) Success(msg string, current ...bool) {
	f.SuccessMsg = msg
	f.set("success", msg, current...)
}
