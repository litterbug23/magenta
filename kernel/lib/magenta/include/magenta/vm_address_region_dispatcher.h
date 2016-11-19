// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <magenta/dispatcher.h>
#include <magenta/state_tracker.h>

#include <lib/user_copy/user_ptr.h>

#include <sys/types.h>

class VmAddressRegion;
class VmMapping;
class VmObject;

class VmAddressRegionDispatcher final : public Dispatcher {
public:
    static status_t Create(mxtl::RefPtr<VmAddressRegion> vmar,
                           mxtl::RefPtr<Dispatcher>* dispatcher,
                           mx_rights_t* rights);

    ~VmAddressRegionDispatcher() final;
    mx_obj_type_t get_type() const final { return MX_OBJ_TYPE_VMAR; }

    // TODO(teisenbe): Make this the planned batch interface
    mx_status_t Allocate(size_t offset, size_t size, uint32_t flags,
                         mxtl::RefPtr<VmAddressRegion>* out);

    mx_status_t Destroy();

    mx_status_t Map(size_t vmar_offset,
                    mxtl::RefPtr<VmObject> vmo, uint64_t vmo_offset, size_t len,
                    uint32_t vmar_flags, uint arch_mmu_flags, mxtl::RefPtr<VmMapping>* out);

    mx_status_t Protect(size_t offset, size_t len, uint arch_mmu_flags);

    mx_status_t Unmap(size_t offset, size_t len);

    mxtl::RefPtr<VmAddressRegion> vmar() const { return vmar_; }

private:
    explicit VmAddressRegionDispatcher(mxtl::RefPtr<VmAddressRegion> vmar);

    mxtl::RefPtr<VmAddressRegion> vmar_;
};
