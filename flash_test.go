// Copyright 2018 The Macaron Authors
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

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/macaron.v1"
)

func Test_Flash(t *testing.T) {
	Convey("Test flash", t, func() {
		m := macaron.New()
		m.Use(Sessioner())
		m.Get("/set", func(f *Flash) string {
			f.Success("success")
			f.Error("error")
			f.Warning("warning")
			f.Info("info")
			return ""
		})
		m.Get("/get", func() {})

		resp := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/set", nil)
		So(err, ShouldBeNil)
		m.ServeHTTP(resp, req)

		resp = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/get", nil)
		So(err, ShouldBeNil)
		req.Header.Set("Cookie", "macaron_flash=error%3Derror%26info%3Dinfo%26success%3Dsuccess%26warning%3Dwarning; Path=/")
		m.ServeHTTP(resp, req)
	})
}
