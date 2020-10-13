// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build go1.13
// +build !go1.17

// Check reflect.Value layout and flag values when updating Go version.

package state

import (
	"reflect"
	"unsafe"
)

// rwValue returns a copy of obj that is usable in assignments, even if
// obj was obtained by the use of unexported struct fields.
func rwValue(obj reflect.Value) reflect.Value {
	rwobj := obj
	rv := (*reflectValue)(unsafe.Pointer(&rwobj))
	rv.flag &^= reflectFlagRO
	return rwobj
}

type reflectValue struct {
	typ  unsafe.Pointer
	ptr  unsafe.Pointer
	flag uintptr
}

const (
	reflectFlagStickyRO uintptr = 1 << 5
	reflectFlagEmbedRO  uintptr = 1 << 6
	reflectFlagRO               = reflectFlagStickyRO | reflectFlagEmbedRO
)
