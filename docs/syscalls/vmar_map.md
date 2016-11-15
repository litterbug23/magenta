# mx_vmar_map

## NAME

vmar_map - add a memory mapping

## SYNOPSIS

```
#include <magenta/syscalls.h>

mx_status_t mx_vmar_map(mx_handle_t vmar, size_t vmar_offset,
                        mx_handle_t vmo, size_t vmo_offset, size_t len,
                        uint32_t map_flags, void** mapped_addr)
```

## DESCRIPTION

Maps the given VMO into the given virtual memory address region.  The mapping
retains a reference to the underlying virtual memory object, which means
closing the VMO handle does not remove the mapping added by this function.

*map_flags* is a bit vector of the following flags:
- **MX_VM_FLAG_SPECIFIC**  Use the *vmar_offset* to place the mapping, invalid if
  vmar does not have the **MX_VM_FLAG_CAN_MAP_SPECIFIC** permission. It is an error
  to specify an address range that overlaps with another VMAR or mapping.
- **MX_VM_FLAG_SPECIFIC_OVERWRITE**  Same as **MX_VM_FLAG_SPECIFIC**, but can
  overlap another mapping.  It is still an error to overlap another VMAR.  If
  the range meets these requirements, it will atomically (with respect to all
  other map/unmap operations) replace existing mappings in the area.
- **MX_VM_FLAG_PERM_READ**  Map *vmo* as readable.  It is an error if *vmar*
  does not have *MX_VM_FLAG_CAN_MAP_READ* permissions, the *vmar* handle does
  not have the *MX_RIGHT_READ* right, or the *vmo* handle does not have the
  *MX_RIGHT_READ* right.
- **MX_VM_FLAG_PERM_WRITE**  Map *vmo* as writable.  It is an error if *vmar*
  does not have *MX_VM_FLAG_CAN_MAP_WRITE* permissions, the *vmar* handle does
  not have the *MX_RIGHT_WRITE* right, or the *vmo* handle does not have the
  *MX_RIGHT_WRITE* right.
- **MX_VM_FLAG_PERM_EXECUTE**  Map *vmo* as executable.  It is an error if *vmar*
  does not have *MX_VM_FLAG_CAN_MAP_EXECUTE* permissions, the *vmar* handle does
  not have the *MX_RIGHT_EXECUTE* right, or the *vmo* handle does not have the
  *MX_RIGHT_EXECUTE* right.

*vmar_offset* must be 0 if *map_flags* does not have **MX_VM_FLAG_SPECIFIC** set.

## RETURN VALUE

**vmar_map**() returns **NO_ERROR** and the base address of the mapping (via
*mapped_addr*) on success.  In the event of failure, a negative error value is
returned.

## ERRORS

## NOTES

A virtual memory object can be larger than the address space, which means you
should check for overflow before converting the **uint64_t** size of the VMO to
**vmar_map**'s **mx_size_t** *len* parameter.

**MX_VM_FLAG_SPECIFIC_OVERWRITE** is not implemented.

## SEE ALSO

[vmar_destroy](vmar_destroy.md).
[vmar_protect](vmar_protect.md).
[vmar_unmap](vmar_unmap.md).
