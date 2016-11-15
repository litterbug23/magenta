# mx_vmar_unmap

## NAME

vmar_unmap - unmap a memory mapping

## SYNOPSIS

```
#include <magenta/syscalls.h>

mx_status_t mx_vmar_unmap(mx_handle_t vmar_handle,
                          mx_size_t offset, mx_size_t len);
```

## DESCRIPTION

**vmar_unmap**() unmaps all VMO mappings and destroys (as if **vmar_destroy**
were called) all sub-regions within the given range.  Note that this operation
is logically recursive.

## RETURN VALUE

**vmar_unmap**() returns **NO_ERROR** on success.

## ERRORS

**ERR_INVALID_ARGS**  *vmar_handle* isn't a valid VMAR handle

## NOTES

Currently *len* must be either 0, or *offset* and *len* must completely
describe either a single mapping or sub-region.

## SEE ALSO

[vmar_destroy](vmar_destroy.md).
[vmar_map](vmar_map.md).
[vmar_protect](vmar_protect.md).
