// Copyright 2016 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#pragma once

#include <assert.h>
#include <kernel/mutex.h>
#include <kernel/vm/vm_object.h>
#include <kernel/vm/vm_page_list.h>
#include <mxtl/deleter.h>
#include <mxtl/intrusive_double_list.h>
#include <mxtl/intrusive_wavl_tree.h>
#include <mxtl/ref_counted.h>
#include <mxtl/ref_ptr.h>
#include <stdint.h>

// Creation flags for VmAddressRegion and VmMappings

// When randomly allocating subregions, reduce sprawl (hint).
// Currently ignored, since randomization is not yet implemented.
// TODO(teisenbe): Remove this comment when randomization is implemented.
#define VMAR_FLAG_COMPACT (1 << 0)
// Request that the new region be at the specified offset in its parent region.
#define VMAR_FLAG_SPECIFIC (1 << 1)
// Allow VmMappings to be created inside the new region with the SPECIFIC flag.
#define VMAR_FLAG_CAN_MAP_SPECIFIC (1 << 2)
// Allow VmMappings to be created inside the new region with read permissions.
#define VMAR_FLAG_CAN_MAP_READ (1 << 3)
// Allow VmMappings to be created inside the new region with write permissions.
#define VMAR_FLAG_CAN_MAP_WRITE (1 << 4)
// Allow VmMappings to be created inside the new region with execute permissions.
#define VMAR_FLAG_CAN_MAP_EXEC (1 << 5)

#define VMAR_RWX_FLAGS (VMAR_FLAG_CAN_MAP_READ | VMAR_FLAG_CAN_MAP_WRITE | VMAR_FLAG_CAN_MAP_EXEC)

class VmAspace;

// forward declarations
class VmAddressRegion;
class VmMapping;

// A VmAddressRegion represents a contiguous region of the virtual address
// space.  It is partitioned by non-overlapping children of the following types:
// 1) child VmAddressRegion
// 2) child VmMapping (leafs that map VmObjects into the address space)
// 3) gaps (logical, not actually objects).
//
// VmAddressRegionOrMapping represents a tagged union of the two types.
//
// A VmAddressRegion may be in one of two states: ALIVE or DEAD.  If it is
// ALIVE, then the VmAddressRegion is a description of the virtual memory
// mappings of the address range it represents in its parent VmAspace.  If it is
// DEAD, then the VmAddressRegion is invalid and has no meaning.
class VmAddressRegionOrMapping : public mxtl::RefCounted<VmAddressRegionOrMapping> {
public:
    // If a VMO-mapping, unmap all pages and remove dependency on vm object it has a ref to.
    // Otherwise recursively destroy child VMARs and transition to the DEAD state.
    //
    // Returns NO_ERROR on success, ERR_BAD_STATE if already dead, and other
    // values on error (typically unmap failure).
    status_t Destroy();

    // accessors
    vaddr_t base() const { return base_; }
    size_t size() const { return size_; }
    uint32_t flags() const { return flags_; }

    // Recursively compute the number of allocated pages within this region
    virtual size_t AllocatedPages() const = 0;

    // Subtype information and safe down-casting
    virtual bool is_mapping() const = 0;
    mxtl::RefPtr<VmAddressRegion> as_vm_address_region();
    mxtl::RefPtr<VmMapping> as_vm_mapping();

    // Page fault in an address within the region.  Recursively traverses
    // the regions to find the target mapping, if it exists.
    virtual status_t PageFault(vaddr_t va, uint pf_flags) = 0;

    // WAVL tree key function
    vaddr_t GetKey() const { return base(); }

    // Dump debug info
    virtual void Dump(uint depth = 0) const = 0;

protected:
    // friend VmAddressRegion so it can access DestroyLocked
    friend VmAddressRegion;

    friend mxtl::default_delete<VmAddressRegionOrMapping>;
    // destructor, should only be invoked from RefPtr
    virtual ~VmAddressRegionOrMapping();

    enum class LifeCycleState {
        ALIVE,
        DEAD
    };

    VmAddressRegionOrMapping(uint32_t magic, LifeCycleState state, vaddr_t base, size_t size,
                             uint32_t flags, VmAspace& aspace, VmAddressRegion* parent,
                             const char* name);

    // Version of Destroy() that does not acquire the aspace lock
    virtual status_t DestroyLocked() = 0;

    // magic value
    uint32_t magic_;

    // current state of the VMAR.  If LifeCycleState::DEAD, then all other
    // fields are invalid.
    LifeCycleState state_ = LifeCycleState::ALIVE;

    // address/size within the container address space
    vaddr_t base_;
    size_t size_;

    // flags from VMAR creation time
    uint32_t flags_;

    // pointer back to our member address space.  The aspace's lock is used
    // to serialize all modifications.  Will be null after Destroy().
    mxtl::RefPtr<VmAspace> aspace_;

    // pointer back to our parent region (nullptr if root)
    VmAddressRegion* parent_;

    struct WAVLTreeTraits {
        static mxtl::WAVLTreeNodeState<mxtl::RefPtr<VmAddressRegionOrMapping>, bool>& node_state(VmAddressRegionOrMapping& obj) {
            return obj.subregion_list_node_;
        }
    };

    // node for element in list of parent's children.
    mxtl::WAVLTreeNodeState<mxtl::RefPtr<VmAddressRegionOrMapping>, bool> subregion_list_node_;

    char name_[32];
};

// A representation of a contiguous range of virtual address space
class VmAddressRegion final : public VmAddressRegionOrMapping {
public:
    // Create a root region.  This will span the entire aspace
    static status_t CreateRoot(VmAspace& aspace, uint32_t vmar_flags,
                               mxtl::RefPtr<VmAddressRegion>* out);
    // Create a subregion of this region
    status_t CreateSubVmar(vaddr_t offset, size_t size, uint8_t align_pow2,
                           uint32_t vmar_flags, const char* name,
                           mxtl::RefPtr<VmAddressRegion>* out);
    // Create a VmMapping within this region
    status_t CreateVmMapping(vaddr_t mapping_offset, size_t size, uint8_t align_pow2,
                             uint32_t vmar_flags,
                             mxtl::RefPtr<VmObject> vmo, uint64_t vmo_offset,
                             uint arch_mmu_flags, const char* name,
                             mxtl::RefPtr<VmMapping>* out);

    // Find the child region that contains the given addr.  If addr is in a gap,
    // returns nullptr.  This is a non-recursive search.
    mxtl::RefPtr<VmAddressRegionOrMapping> FindRegion(vaddr_t addr);

    bool is_mapping() const override { return false; }

    size_t AllocatedPages() const override;
    void Dump(uint depth) const override;
    status_t PageFault(vaddr_t va, uint pf_flags) override;

protected:
    static const uint32_t kMagic = 0x564d4152; // VMAR

    friend class VmAspace;
    // constructor for use in creating the kernel aspace singleton
    explicit VmAddressRegion(VmAspace& kernel_aspace);

    friend class VmMapping;
    // Remove *region* from the subregion list
    void RemoveSubregion(VmAddressRegionOrMapping* region);

    friend mxtl::default_delete<VmAddressRegion>;
    ~VmAddressRegion() override;

private:
    // utility so WAVL tree can find the intrusive node for the child list
    using ChildList = mxtl::WAVLTree<vaddr_t, mxtl::RefPtr<VmAddressRegionOrMapping>,
                                     mxtl::DefaultKeyedObjectTraits<vaddr_t, VmAddressRegionOrMapping>,
                                     WAVLTreeTraits>;

    DISALLOW_COPY_ASSIGN_AND_MOVE(VmAddressRegion);

    // private constructors, use Create...() instead
    VmAddressRegion(VmAspace& aspace, vaddr_t base, size_t size, uint32_t vmar_flags);
    VmAddressRegion(VmAddressRegion& parent, vaddr_t base, size_t size, uint32_t vmar_flags, const char* name);

    // Version of FindRegion() that does not acquire the aspace lock
    mxtl::RefPtr<VmAddressRegionOrMapping> FindRegionLocked(vaddr_t addr);

    // Version of Destroy() that does not acquire the aspace lock
    status_t DestroyLocked() override;

    // Helper to share code between CreateSubVmar and CreateVmMapping
    status_t CreateSubVmarInternal(vaddr_t offset, size_t size, uint8_t align_pow2,
                                   uint32_t vmar_flags,
                                   mxtl::RefPtr<VmObject> vmo, uint64_t vmo_offset,
                                   uint arch_mmu_flags, const char* name,
                                   mxtl::RefPtr<VmAddressRegionOrMapping>* out);

    // internal utilities for interacting with the children list

    // returns true if it would be valid to create a child in the
    // range [base, base+size)
    bool IsRangeAvailable(vaddr_t base, size_t size);

    // returns true if we can meet the allocation between the given children,
    // and if so populates pva with the base address to use.
    // TODO(teisenbe): Get rid of this once we implement randomization
    bool CheckGap(const ChildList::iterator& prev, const ChildList::iterator& next,
                  vaddr_t* pva, vaddr_t search_base, vaddr_t align,
                  size_t region_size, size_t min_gap, uint arch_mmu_flags);

    // search for a spot to allocate for a region of a given size
    vaddr_t AllocSpot(vaddr_t base, size_t size, uint8_t align_pow2,
                      size_t min_alloc_gap, uint arch_mmu_flags);

    // list of subregions, indexed by base address
    ChildList subregions_;
};

// A representation of the mapping of a VMO into the address space
class VmMapping final : public VmAddressRegionOrMapping,
                        public mxtl::DoublyLinkedListable<VmMapping *> {
public:
    // accessors for VMO-mapping state
    uint arch_mmu_flags() const { return arch_mmu_flags_; }
    uint64_t object_offset() const { return object_offset_; }
    mxtl::RefPtr<VmObject> vmo() { return object_; };

    // map in pages from the underlying vm object, optionally committing pages as it goes
    status_t MapRange(size_t offset, size_t len, bool commit);

    // unmap the region of memory in the container address space
    status_t Unmap();

    // change access permissions for this mapping
    status_t Protect(uint arch_mmu_flags);

    bool is_mapping() const override { return true; }

    size_t AllocatedPages() const override;
    void Dump(uint depth) const override;
    status_t PageFault(vaddr_t va, uint pf_flags) override;

protected:
    static const uint32_t kMagic = 0x564d4150; // VMAP

    friend mxtl::default_delete<VmMapping>;
    ~VmMapping() override;

    // private apis from VmObject land
    friend class VmObjectPaged;

    // unmap any pages that map the passed in vmo range. May not intersect with this range
    status_t UnmapVmoRangeLocked(uint64_t start, uint64_t size);

private:
    DISALLOW_COPY_ASSIGN_AND_MOVE(VmMapping);

    // allow VmAddressRegion to manipulate VmMapping internals for construction
    // and bookkeeping
    friend class VmAddressRegion;

    // private constructors, use VmAddressRegion::Create...() instead
    VmMapping(VmAddressRegion& parent, vaddr_t base, size_t size, mxtl::RefPtr<VmObject> vmo,
              uint64_t vmo_offset, uint arch_mmu_flags, const char* name);

    // Version of Destroy() that does not acquire the aspace lock
    status_t DestroyLocked() override;

    // Version of Unmap() that does not acquire the aspace lock
    status_t UnmapLocked();

    // pointer and region of the object we are mapping
    mxtl::RefPtr<VmObject> object_;
    uint64_t object_offset_ = 0;

    // cached mapping flags (read/write/user/etc)
    uint arch_mmu_flags_;
};
