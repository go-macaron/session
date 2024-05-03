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
	"fmt"
	"log/slog"
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

var _ session.RawStore = (*RedisStore)(nil)

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

// Prefix returns the prefix used for session key
func (s *RedisStore) Prefix() string {
	return s.prefix
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

type RedisHubStore struct {
	c               *redis.Client
	uid, sessPrefix string
	lock            sync.RWMutex
	cleanup         map[string]struct{}
	data            map[string]time.Time
}

var _ session.HubStore = (*RedisHubStore)(nil)

func NewRedisHubStore(c *redis.Client, uid, sessPrefix string, data map[string]time.Time) (*RedisHubStore, error) {
	return &RedisHubStore{
		c:          c,
		uid:        uid,
		data:       data,
		cleanup:    make(map[string]struct{}),
		sessPrefix: sessPrefix,
	}, nil
}

func getHubStoreKey(uid string) string {
	return fmt.Sprintf("sessions.user.%v", uid)
}

func getHubStoreKeyPattern() string {
	return "sessions.user.*"
}

func (h *RedisHubStore) Add(sessionKey string, exp time.Time) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.data[sessionKey] = exp
	return nil
}

func (h *RedisHubStore) Remove(sessionKey string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	delete(h.data, sessionKey)
	h.cleanup[sessionKey] = struct{}{}
	return nil
}

func (h *RedisHubStore) RemoveAll() error {
	h.lock.Lock()
	defer h.lock.Unlock()

	for k := range h.data {
		h.cleanup[k] = struct{}{}
	}
	h.data = make(map[string]time.Time)
	return nil
}

func (h *RedisHubStore) RemoveExcept(sessionKey string) error {
	h.lock.Lock()
	defer h.lock.Unlock()

	for k := range h.data {
		h.cleanup[k] = struct{}{}
	}
	delete(h.cleanup, sessionKey)

	backupVal := h.data[sessionKey]
	_ = h.RemoveAll()
	_ = h.Add(sessionKey, backupVal)
	return nil
}

func (h *RedisHubStore) flushExpired() error {
	backupData := make(map[string]time.Time)
	for k, exp := range h.data {
		backupData[k] = exp
	}
	currentTime := time.Now()
	for k, exp := range backupData {
		if exp.Before(currentTime) {
			h.cleanup[k] = struct{}{}
			delete(h.data, k)
		}
	}

	return nil
}

func (h *RedisHubStore) ReleaseHubData() error {
	h.lock.Lock()
	defer h.lock.Unlock()

	if len(h.data) == 0 {
		return nil
	}
	_ = h.flushExpired()

	convertedMap := make(map[any]any)
	for k, exp := range h.data {
		convertedMap[k] = exp
	}

	data, err := session.EncodeGob(convertedMap)
	if err != nil {
		return err
	}

	_ = h.executeCleanup()

	hubKey := getHubStoreKey(h.uid)
	return h.c.Set(ctx, hubKey, string(data), 0).Err()
}

func (h *RedisHubStore) executeCleanup() error {
	keys := make([]string, 0)
	for k := range h.cleanup {
		keys = append(keys, h.sessPrefix+k)
	}

	var cleanupBatch = 100
	var idx = 0
	for idx < len(keys) {
		pipeline := h.c.Pipeline()
		for i := idx; i < min(len(keys), idx+cleanupBatch); i++ {
			pipeline.Del(ctx, keys[i])
		}
		idx += cleanupBatch

		_, err := pipeline.Exec(ctx)
		if err != nil {
			slog.Error("failed to cleanup sessions: %v", err)
			continue
		}
	}
	h.cleanup = make(map[string]struct{})

	return nil
}

// RedisProvider represents a redis session provider implementation.
type RedisProvider struct {
	c        *redis.Client
	duration time.Duration
	prefix   string
}

var _ session.Provider = (*RedisProvider)(nil)

// Init initializes redis session provider.
// configs: network=tcp,addr=:6379,password=macaron,db=0,pool_size=100,idle_timeout=180,prefix=session;
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
		kv["_old_uid"] = "0"
		kv["exp"] = time.Now().Add(p.duration).Add(time.Minute)
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

func (p *RedisProvider) checkKeyExistence(key string) bool {
	count, err := p.c.Exists(ctx, key).Result()
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
func (p *RedisProvider) GC() {
	keyPattern := getHubStoreKeyPattern()
	countBatchProcess := int64(100)

	var cursor uint64
	var err error
	var keys []string
	var sessionHubData = make(map[string]any)
	for {
		keys, cursor, err = p.c.Scan(ctx, cursor, keyPattern, countBatchProcess).Result()
		if err != nil {
			slog.Error("garbage collection error:: failed to scan pattern %v", keyPattern)
			return
		}
		if cursor == 0 {
			break
		}

		pipeline := p.c.Pipeline()
		var cmds []*redis.StringCmd
		for _, key := range keys {
			cmds = append(cmds, pipeline.Get(ctx, key))
		}

		_, err = pipeline.Exec(ctx)
		if err != nil {
			slog.Error("garbage collection error: failed to execute redis pipeline")
			continue
		}

		for i, cmd := range cmds {
			result, err := cmd.Result()
			if err != nil {
				slog.Error("garbage collection error: %v", err)
				continue
			}
			sessionHubData[keys[i]], err = session.DecodeGob([]byte(result))
			if err != nil {
				slog.Error("garbage collection error: failed to decode values of key: %v", keys[i])
				continue
			}
		}
	}

	for k, data := range sessionHubData {
		parts := strings.Split(k, ".")
		uid := parts[len(parts)-1]

		if data != nil {
			parsedData, ok := data.(map[any]any)
			if !ok {
				slog.Error("")
			}

			actualData := make(map[string]time.Time)
			for k, v := range parsedData {
				key, ok := k.(string)
				if !ok {
					slog.Error("garbage collection error: failed to parse key from interface data")
					continue
				}
				value, ok := v.(time.Time)
				if !ok {
					slog.Error("garbage collection error: failed to parse value from interface data")
					continue
				}

				actualData[key] = value
			}
			hubStore, _ := NewRedisHubStore(p.c, uid, p.prefix, actualData)
			if err = hubStore.ReleaseHubData(); err != nil {
				slog.Error("garbage collection error: failed to release hub data for key: %v, err: %v", k, err.Error())
			}
			continue
		}

		slog.Error("garbage collection error: data is empty for key: %v", k)
	}
}

// ReadSessionHubStore returns all the sessions of user specified by user id
func (p *RedisProvider) ReadSessionHubStore(uid string) (session.HubStore, error) {
	hubKey := getHubStoreKey(uid)
	if !p.checkKeyExistence(hubKey) {
		if err := p.c.Set(ctx, hubKey, "", 0).Err(); err != nil {
			return nil, err
		}
	}

	var hubData = make(map[string]time.Time)
	result, err := p.c.Get(ctx, hubKey).Result()
	if err != nil {
		return nil, err
	}

	if len(result) > 0 {
		m := make(map[any]any)
		m, err = session.DecodeGob([]byte(result))
		if err != nil {
			return nil, err
		}

		for k, exp := range m {
			hubData[k.(string)] = exp.(time.Time)
		}
	}

	return NewRedisHubStore(p.c, uid, p.prefix, hubData)
}

func init() {
	session.Register("redis", &RedisProvider{})
}
