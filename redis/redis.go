// Copyright 2013 Beego Authors
// Copyright 2014 The Macaron Authors
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
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/unknwon/com"
	"gopkg.in/ini.v1"

	"github.com/go-macaron/session"
)

// since we do not use context define global once
var ctx = context.TODO()

// RedisStore represents a redis session store implementation.
type RedisStore struct {
	c           *redis.Client
	prefix, sid string
	duration    time.Duration
	lock        sync.RWMutex
	data        map[interface{}]interface{}
}

// NewRedisStore creates and returns a redis session store.
func NewRedisStore(c *redis.Client, prefix, sid string, dur time.Duration, kv map[interface{}]interface{}) *RedisStore {
	return &RedisStore{
		c:        c,
		prefix:   prefix,
		sid:      sid,
		duration: dur,
		data:     kv,
	}
}

// Set sets value to given key in session.
func (s *RedisStore) Set(key, val interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data[key] = val
	return nil
}

// Get gets value by given key in session.
func (s *RedisStore) Get(key interface{}) interface{} {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.data[key]
}

// Delete delete a key from session.
func (s *RedisStore) Delete(key interface{}) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.data, key)
	return nil
}

// ID returns current session ID.
func (s *RedisStore) ID() string {
	return s.sid
}

// Release releases resource and save data to provider.
func (s *RedisStore) Release() error {
	// Skip encoding if the data is empty
	if len(s.data) == 0 {
		return nil
	}

	data, err := session.EncodeGob(s.data)
	if err != nil {
		return err
	}

	return s.c.Set(ctx, s.prefix+s.sid, string(data), s.duration).Err()
}

// Flush deletes all session data.
func (s *RedisStore) Flush() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.data = make(map[interface{}]interface{})
	return nil
}

// RedisProvider represents a redis session provider implementation.
type RedisProvider struct {
	c        *redis.Client
	duration time.Duration
	prefix   string
}

// Init initializes redis session provider.
// configs: network=tcp,addr=:6379,password=macaron,db=0,pool_size=100,idle_timeout=180,prefix=session,tls=true
func (p *RedisProvider) Init(maxlifetime int64, configs string) (err error) {
	p.duration, err = time.ParseDuration(fmt.Sprintf("%ds", maxlifetime))
	if err != nil {
		return err
	}

	cfg, err := ini.Load([]byte(strings.Replace(configs, ",", "\n", -1)))
	if err != nil {
		return err
	}

	section, err := cfg.GetSection("")
	if err == nil && section != nil && section.Key("ha_mode").Value() == "sentinel" {
		return p.initSentinel(cfg)
	}

	opt := &redis.Options{
		Network: "tcp",
	}
	for k, v := range cfg.Section("").KeysHash() {
		switch k {
		case "network":
			opt.Network = v
		case "addr":
			opt.Addr = v
		case "password":
			opt.Password = v
		case "db":
			opt.DB = com.StrTo(v).MustInt()
		case "pool_size":
			opt.PoolSize = com.StrTo(v).MustInt()
		case "idle_timeout":
			opt.IdleTimeout, err = time.ParseDuration(v + "s")
			if err != nil {
				return fmt.Errorf("error parsing idle timeout: %v", err)
			}
		case "prefix":
			p.prefix = v
		case "ha_mode":
			// avoid panic
		case "tls":
			opt.TLSConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		default:
			return fmt.Errorf("session/redis: unsupported option '%s'", k)
		}
	}

	p.c = redis.NewClient(opt)
	return p.c.Ping(ctx).Err()
}

func (p *RedisProvider) initSentinel(cfg *ini.File) (err error) {
	opt := &redis.FailoverOptions{}

	for k, v := range cfg.Section("").KeysHash() {
		switch k {
		case "master_name":
			opt.MasterName = v
		case "sentinel_Addrs":
			opt.SentinelAddrs = strings.Split(v, "|")
		case "password":
			opt.Password = v
		case "db":
			opt.DB = com.StrTo(v).MustInt()
		case "pool_size":
			opt.PoolSize = com.StrTo(v).MustInt()
		case "dial_timeout":
			opt.DialTimeout, err = time.ParseDuration(v + "s")
			if err != nil {
				return fmt.Errorf("error parsing dial timeout: %v", err)
			}
		case "read_timeout":
			opt.ReadTimeout, err = time.ParseDuration(v + "s")
			if err != nil {
				return fmt.Errorf("error parsing read timeout: %v", err)
			}
		case "write_timeout":
			opt.WriteTimeout, err = time.ParseDuration(v + "s")
			if err != nil {
				return fmt.Errorf("error parsing write timeout: %v", err)
			}
		case "idle_timeout":
			opt.IdleTimeout, err = time.ParseDuration(v + "s")
			if err != nil {
				return fmt.Errorf("error parsing idle timeout: %v", err)
			}
		case "prefix":
			p.prefix = v
		}
	}
	p.c = redis.NewFailoverClient(opt)
	return p.c.Ping(ctx).Err()
}

// Read returns raw session store by session ID.
func (p *RedisProvider) Read(sid string) (session.RawStore, error) {
	psid := p.prefix + sid
	if !p.Exist(sid) {
		if err := p.c.Set(ctx, psid, "", p.duration).Err(); err != nil {
			return nil, err
		}
	}

	var kv map[interface{}]interface{}
	kvs, err := p.c.Get(ctx, psid).Result()
	if err != nil {
		return nil, err
	}
	if len(kvs) == 0 {
		kv = make(map[interface{}]interface{})
	} else {
		kv, err = session.DecodeGob([]byte(kvs))
		if err != nil {
			return nil, err
		}
	}

	return NewRedisStore(p.c, p.prefix, sid, p.duration, kv), nil
}

// Exist returns true if session with given ID exists.
func (p *RedisProvider) Exist(sid string) bool {
	count, err := p.c.Exists(ctx, p.prefix+sid).Result()
	return err == nil && count == 1
}

// Destory deletes a session by session ID.
func (p *RedisProvider) Destory(sid string) error {
	return p.c.Del(ctx, p.prefix+sid).Err()
}

// Regenerate regenerates a session store from old session ID to new one.
func (p *RedisProvider) Regenerate(oldsid, sid string) (_ session.RawStore, err error) {
	poldsid := p.prefix + oldsid
	psid := p.prefix + sid

	if p.Exist(sid) {
		return nil, fmt.Errorf("new sid '%s' already exists", sid)
	} else if !p.Exist(oldsid) {
		// Make a fake old session.
		if err = p.c.Set(ctx, poldsid, "", p.duration).Err(); err != nil {
			return nil, err
		}
	}

	if err = p.c.Rename(ctx, poldsid, psid).Err(); err != nil {
		return nil, err
	}

	var kv map[interface{}]interface{}
	kvs, err := p.c.Get(ctx, psid).Result()
	if err != nil {
		return nil, err
	}

	if len(kvs) == 0 {
		kv = make(map[interface{}]interface{})
	} else {
		kv, err = session.DecodeGob([]byte(kvs))
		if err != nil {
			return nil, err
		}
	}

	return NewRedisStore(p.c, p.prefix, sid, p.duration, kv), nil
}

// Count counts and returns number of sessions.
func (p *RedisProvider) Count() int {
	count, err := p.c.DBSize(ctx).Result()
	if err != nil {
		return 0
	}
	return int(count)
}

// GC calls GC to clean expired sessions.
func (_ *RedisProvider) GC() {}

func init() {
	session.Register("redis", &RedisProvider{})
}
