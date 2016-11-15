// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <err.h>
#include <inttypes.h>
#include <trace.h>

#include <kernel/vm/vm_object.h>
#include <kernel/vm/vm_address_region.h>

#include <lib/user_copy.h>
#include <lib/user_copy/user_ptr.h>

#include <magenta/magenta.h>
#include <magenta/process_dispatcher.h>
#include <magenta/user_copy.h>
#include <magenta/vm_address_region_dispatcher.h>
#include <magenta/vm_object_dispatcher.h>

#include <mxtl/auto_call.h>
#include <mxtl/ref_ptr.h>

#include "syscalls_priv.h"

#define LOCAL_TRACE 0

namespace {

bool is_valid_mapping_protection(uint32_t flags) {
    switch (flags & (MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE)) {
        case 0: // no way to express no permissions
        case MX_VM_FLAG_PERM_WRITE:
            // no way to express write only
            return false;
        default: return true;
    }
}

// Split out the syscall flags into vmar flags and mmu flags.  Note that this
// does not validate that the request protections in *flags* are valid.  For
// that use is_valid_mapping_protection()
status_t split_syscall_flags(uint32_t flags, uint32_t* vmar_flags, uint* arch_mmu_flags) {
    // Figure out arch_mmu_flags
    uint mmu_flags = ARCH_MMU_FLAG_PERM_USER;
    switch (flags & (MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE)) {
        case MX_VM_FLAG_PERM_READ:
            mmu_flags |= ARCH_MMU_FLAG_PERM_READ;
            break;
        case MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE:
            mmu_flags |= ARCH_MMU_FLAG_PERM_READ | ARCH_MMU_FLAG_PERM_WRITE;
            break;
    }

    if (flags & MX_VM_FLAG_PERM_EXECUTE) {
        mmu_flags |= ARCH_MMU_FLAG_PERM_EXECUTE;
    }

    // Mask out arch_mmu_flags options
    flags &= ~(MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE | MX_VM_FLAG_PERM_EXECUTE);

    // Figure out vmar flags
    uint32_t vmar = 0;
    if (flags & MX_VM_FLAG_COMPACT) {
        vmar |= VMAR_FLAG_COMPACT;
        flags &= ~MX_VM_FLAG_COMPACT;
    }
    if (flags & MX_VM_FLAG_SPECIFIC) {
        vmar |= VMAR_FLAG_SPECIFIC;
        flags &= ~MX_VM_FLAG_SPECIFIC;
    }
    if (flags & MX_VM_FLAG_CAN_MAP_SPECIFIC) {
        vmar |= VMAR_FLAG_CAN_MAP_SPECIFIC;
        flags &= ~MX_VM_FLAG_CAN_MAP_SPECIFIC;
    }
    if (flags & MX_VM_FLAG_CAN_MAP_READ) {
        vmar |= VMAR_FLAG_CAN_MAP_READ;
        flags &= ~MX_VM_FLAG_CAN_MAP_READ;
    }
    if (flags & MX_VM_FLAG_CAN_MAP_WRITE) {
        vmar |= VMAR_FLAG_CAN_MAP_WRITE;
        flags &= ~MX_VM_FLAG_CAN_MAP_WRITE;
    }
    if (flags & MX_VM_FLAG_CAN_MAP_EXECUTE) {
        vmar |= VMAR_FLAG_CAN_MAP_EXEC;
        flags &= ~MX_VM_FLAG_CAN_MAP_EXECUTE;
    }

    if (flags != 0)
        return ERR_INVALID_ARGS;

    *vmar_flags = vmar;
    *arch_mmu_flags = mmu_flags;
    return NO_ERROR;
}

} // namespace

mx_status_t sys_vmar_allocate(mx_handle_t parent_vmar_handle,
                    mx_size_t offset, mx_size_t size, uint32_t flags,
                    user_ptr<mx_handle_t> child_vmar, user_ptr<void*> child_addr) {

    auto up = ProcessDispatcher::GetCurrent();

    // lookup the dispatcher from handle
    mxtl::RefPtr<VmAddressRegionDispatcher> vmar;
    mx_rights_t vmar_rights;
    mx_status_t status = up->GetDispatcher(parent_vmar_handle, &vmar, &vmar_rights);
    if (status != NO_ERROR)
        return status;

    uint32_t vmar_flags;
    uint arch_mmu_flags;
    status = split_syscall_flags(flags, &vmar_flags, &arch_mmu_flags);
    if (status != NO_ERROR)
        return status;

    // Check if any MMU-related flags were requested (USER is always present)
    if (arch_mmu_flags != ARCH_MMU_FLAG_PERM_USER) {
        return ERR_INVALID_ARGS;
    }

    // TODO(teisenbe): Check for unexpected vmar_flags and fail if we find any

    // Create the new VMAR
    mxtl::RefPtr<VmAddressRegion> new_vmar;
    status = vmar->Allocate(offset, size, vmar_flags, &new_vmar);
    if (status != NO_ERROR)
        return status;

    // Setup a handler to destroy the new VMAR if the syscall is unsuccessful.
    // Note that new_vmar is being passed by value, so a new reference is held
    // there.
    auto cleanup_handler = mxtl::MakeAutoCall([new_vmar]() {
        new_vmar->Destroy();
    });

    if (child_addr.copy_to_user(reinterpret_cast<void*>(new_vmar->base())) != NO_ERROR)
        return ERR_INVALID_ARGS;

    // Create a dispatcher
    mxtl::RefPtr<Dispatcher> dispatcher;
    mx_rights_t new_rights;
    status = VmAddressRegionDispatcher::Create(mxtl::move(new_vmar), &dispatcher, &new_rights);
    if (status != NO_ERROR)
        return status;

    // Create a handle and attach the dispatcher to it
    HandleUniquePtr handle(MakeHandle(mxtl::move(dispatcher), new_rights));
    if (!handle)
        return ERR_NO_MEMORY;

    if (child_vmar.copy_to_user(up->MapHandleToValue(handle.get())) != NO_ERROR)
        return ERR_INVALID_ARGS;

    up->AddHandle(mxtl::move(handle));
    cleanup_handler.cancel();
    return NO_ERROR;
}

mx_status_t sys_vmar_destroy(mx_handle_t vmar_handle) {
    auto up = ProcessDispatcher::GetCurrent();

    // lookup the dispatcher from handle
    mxtl::RefPtr<VmAddressRegionDispatcher> vmar;
    mx_rights_t vmar_rights;
    mx_status_t status = up->GetDispatcher(vmar_handle, &vmar, &vmar_rights);
    if (status != NO_ERROR)
        return status;

    return vmar->Destroy();
}

mx_status_t sys_vmar_map(mx_handle_t vmar_handle, mx_size_t vmar_offset,
                    mx_handle_t vmo_handle, uint64_t vmo_offset, mx_size_t len, uint32_t flags,
                    user_ptr<void*> mapped_addr) {
    auto up = ProcessDispatcher::GetCurrent();

    // lookup the VMAR dispatcher from handle
    mxtl::RefPtr<VmAddressRegionDispatcher> vmar;
    mx_rights_t vmar_rights;
    mx_status_t status = up->GetDispatcher(vmar_handle, &vmar, &vmar_rights);
    if (status != NO_ERROR) {
        // TODO(teisenbe): always bail here once we get rid of the compat layer
        if (status != ERR_WRONG_TYPE)
            return status;

        // As a temporary compatibility measure, treat a process handle as a
        // root VMAR handle.
        mxtl::RefPtr<ProcessDispatcher> proc;
        mx_rights_t proc_rights;
        status = up->GetDispatcher(vmar_handle, &proc, &proc_rights);
        if (status != NO_ERROR)
            return status;

        mxtl::RefPtr<Dispatcher> new_dispatcher;
        status = VmAddressRegionDispatcher::Create(proc->aspace()->root_vmar(), &new_dispatcher,
                                                   &vmar_rights);
        if (status != NO_ERROR)
            return status;
        vmar = DownCastDispatcher<VmAddressRegionDispatcher>(mxtl::move(new_dispatcher));

        if (vmar_offset != 0) {
            if (vmar_offset < vmar->vmar()->base()) {
                return ERR_INVALID_ARGS;
            }
            vmar_offset -= vmar->vmar()->base();
        }
    }

    // lookup the VMO dispatcher from handle
    mxtl::RefPtr<VmObjectDispatcher> vmo;
    mx_rights_t vmo_rights;
    status = up->GetDispatcher(vmo_handle, &vmo, &vmo_rights);
    if (status != NO_ERROR)
        return status;

    // test to see if we should even be able to map this
    if (!(vmo_rights & MX_RIGHT_MAP)) {
        return ERR_ACCESS_DENIED;
    }

    if (!is_valid_mapping_protection(flags))
        return ERR_INVALID_ARGS;

    // Split flags into vmar_flags and arch_mmu_flags
    uint32_t vmar_flags;
    uint arch_mmu_flags;
    status = split_syscall_flags(flags, &vmar_flags, &arch_mmu_flags);
    if (status != NO_ERROR)
        return status;

    // test to see if the requested mapping protections are allowed
    if ((flags & MX_VM_FLAG_PERM_READ) &&
        (!(vmo_rights & MX_RIGHT_READ) || !(vmar_rights & MX_RIGHT_READ))) {
        return ERR_ACCESS_DENIED;
    }
    if ((flags & MX_VM_FLAG_PERM_WRITE) &&
        (!(vmo_rights & MX_RIGHT_WRITE) || !(vmar_rights & MX_RIGHT_WRITE))) {
        return ERR_ACCESS_DENIED;
    }
    if ((flags & MX_VM_FLAG_PERM_EXECUTE) &&
        (!(vmo_rights & MX_RIGHT_EXECUTE) || !(vmar_rights & MX_RIGHT_EXECUTE))) {
        return ERR_ACCESS_DENIED;
    }

    // TODO(teisenbe): Check for unexpected vmar_flags and fail if we find any

    mxtl::RefPtr<VmMapping> vm_mapping;
    status = vmar->Map(vmar_offset, vmo->vmo(), vmo_offset, len, vmar_flags, arch_mmu_flags,
                       &vm_mapping);
    if (status != NO_ERROR)
        return status;

    // Setup a handler to destroy the new VMAR if the syscall is unsuccessful.
    auto cleanup_handler = mxtl::MakeAutoCall([vm_mapping]() {
        vm_mapping->Destroy();
    });

    if (mapped_addr.copy_to_user(reinterpret_cast<void*>(vm_mapping->base())) != NO_ERROR)
        return ERR_INVALID_ARGS;

    cleanup_handler.cancel();
    return NO_ERROR;
}

mx_status_t sys_vmar_unmap(mx_handle_t vmar_handle, mx_size_t offset, mx_size_t len) {
    auto up = ProcessDispatcher::GetCurrent();

    // lookup the dispatcher from handle
    mxtl::RefPtr<VmAddressRegionDispatcher> vmar;
    mx_rights_t vmar_rights;
    mx_status_t status = up->GetDispatcher(vmar_handle, &vmar, &vmar_rights);
    if (status != NO_ERROR) {
        // TODO(teisenbe): always bail here once we get rid of the compat layer
        if (status != ERR_WRONG_TYPE)
            return status;

        // As a temporary compatibility measure, treat a process handle as a
        // root VMAR handle.
        mxtl::RefPtr<ProcessDispatcher> proc;
        mx_rights_t proc_rights;
        status = up->GetDispatcher(vmar_handle, &proc, &proc_rights);
        if (status != NO_ERROR)
            return status;

        mxtl::RefPtr<Dispatcher> new_dispatcher;
        status = VmAddressRegionDispatcher::Create(proc->aspace()->root_vmar(), &new_dispatcher,
                                                   &vmar_rights);
        if (status != NO_ERROR)
            return status;
        vmar = DownCastDispatcher<VmAddressRegionDispatcher>(mxtl::move(new_dispatcher));

        if (offset < vmar->vmar()->base()) {
            return ERR_INVALID_ARGS;
        }
        offset -= vmar->vmar()->base();
    }

    return vmar->Unmap(offset, len);
}

mx_status_t sys_vmar_protect(mx_handle_t vmar_handle, mx_size_t offset, mx_size_t len, uint32_t prot) {
    auto up = ProcessDispatcher::GetCurrent();

    // lookup the dispatcher from handle
    mxtl::RefPtr<VmAddressRegionDispatcher> vmar;
    mx_rights_t vmar_rights;
    mx_status_t status = up->GetDispatcher(vmar_handle, &vmar, &vmar_rights);
    if (status != NO_ERROR) {
        // TODO(teisenbe): always bail here once we get rid of the compat layer
        if (status != ERR_WRONG_TYPE)
            return status;

        // As a temporary compatibility measure, treat a process handle as a
        // root VMAR handle.
        mxtl::RefPtr<ProcessDispatcher> proc;
        mx_rights_t proc_rights;
        status = up->GetDispatcher(vmar_handle, &proc, &proc_rights);
        if (status != NO_ERROR)
            return status;

        mxtl::RefPtr<Dispatcher> new_dispatcher;
        status = VmAddressRegionDispatcher::Create(proc->aspace()->root_vmar(), &new_dispatcher,
                                                   &vmar_rights);

        if (status != NO_ERROR)
            return status;
        vmar = DownCastDispatcher<VmAddressRegionDispatcher>(mxtl::move(new_dispatcher));

        if (offset < vmar->vmar()->base()) {
            return ERR_INVALID_ARGS;
        }
        offset -= vmar->vmar()->base();
    }

    if (!is_valid_mapping_protection(prot))
        return ERR_INVALID_ARGS;

    uint32_t vmar_flags;
    uint arch_mmu_flags;
    status = split_syscall_flags(prot, &vmar_flags, &arch_mmu_flags);
    if (status != NO_ERROR)
        return status;

    if ((prot & MX_VM_FLAG_PERM_READ) && !(vmar_rights & MX_RIGHT_READ))
        return ERR_ACCESS_DENIED;
    if ((prot & MX_VM_FLAG_PERM_WRITE) && !(vmar_rights & MX_RIGHT_WRITE))
        return ERR_ACCESS_DENIED;
    if ((prot & MX_VM_FLAG_PERM_EXECUTE) && !(vmar_rights & MX_RIGHT_EXECUTE))
        return ERR_ACCESS_DENIED;

    // TODO(teisenbe): Bail if any unexpected arch_mmu_flags

    // This request does not allow any VMAR flags to be set
    if (vmar_flags)
        return ERR_INVALID_ARGS;

    // TODO(teisenbe): Check permissions?
    // TODO(teisenbe): Cap permissions at the level of the original VMO handle
    return vmar->Protect(offset, len, arch_mmu_flags);
}
