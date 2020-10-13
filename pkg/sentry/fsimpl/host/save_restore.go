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

package host

import (
	"fmt"
	"syscall"

	"gvisor.dev/gvisor/pkg/fdnotifier"
)

// beforeSave is invoked by stateify.
func (i *inode) beforeSave() {
	if !i.savable {
		panic("host.inode is not savable")
	}
}

// afterLoad is invoked by stateify.
func (i *inode) afterLoad() {
	if i.wouldBlock {
		if err := syscall.SetNonblock(i.hostFD, true); err != nil {
			panic(fmt.Sprintf("host.inode.afterLoad: failed to set host FD %d non-blocking: %v", i.hostFD, err))
		}
		if err := fdnotifier.AddFD(int32(i.hostFD), &i.queue); err != nil {
			panic(fmt.Sprintf("host.inode.afterLoad: fdnotifier.AddFD(%d) failed: %v", i.hostFD, err))
		}
	}
}

// afterLoad is invoked by stateify.
func (i *inodePlatformFile) afterLoad() {
	if i.fileMapper.IsInited() {
		// Ensure that we don't call i.fileMapper.Init() again.
		i.fileMapperInitOnce.Do(func() {})
	}
}
