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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Unknwon/macaron"
	. "github.com/smartystreets/goconvey/convey"
)

func Test_MemProvider(t *testing.T) {
	Convey("Test memory session provider", t, func() {

		Convey("Basic operation", func() {
			m := macaron.New()
			m.Use(Sessioner())

			m.Get("/", func(sess Store) {
				sess.Set("uname", "unknwon")
			})
			m.Get("/get", func(ctx *macaron.Context, sess Store) {
				sid := sess.ID()
				So(sid, ShouldNotBeEmpty)
				uname := sess.Get("uname")
				So(uname, ShouldNotBeNil)
				So(uname, ShouldEqual, "unknwon")

				So(sess.Count(), ShouldEqual, 1)

				So(sess.Delete("uname"), ShouldBeNil)
				So(sess.Get("uname"), ShouldBeNil)

				So(sess.Destory(ctx), ShouldBeNil)
				So(sess.Count(), ShouldEqual, 0)
			})

			resp := httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/", nil)
			So(err, ShouldBeNil)
			m.ServeHTTP(resp, req)

			cookie := resp.Header().Get("Set-Cookie")

			resp = httptest.NewRecorder()
			req, err = http.NewRequest("GET", "/get", nil)
			So(err, ShouldBeNil)

			req.Header.Set("Cookie", cookie)
			m.ServeHTTP(resp, req)
		})

		Convey("GC session", func() {
			m := macaron.New()
			m.Use(Sessioner(Options{
				Config: Config{
					Gclifetime: 1,
				},
			}))

			m.Get("/", func(sess Store) {
				sess.Set("uname", "unknwon")
				So(sess.ID(), ShouldNotBeEmpty)
				uname := sess.Get("uname")
				So(uname, ShouldNotBeNil)
				So(uname, ShouldEqual, "unknwon")

				So(sess.Flush(), ShouldBeNil)
				So(sess.Get("uname"), ShouldBeNil)

				time.Sleep(2 * time.Second)
				sess.GC()
				So(sess.Count(), ShouldEqual, 0)
			})

			resp := httptest.NewRecorder()
			req, err := http.NewRequest("GET", "/", nil)
			So(err, ShouldBeNil)
			m.ServeHTTP(resp, req)
		})
	})
}
