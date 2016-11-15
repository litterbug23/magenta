// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <magenta/syscalls.h>
#include <unittest/unittest.h>
#include <sys/mman.h>

namespace {

static const char kProcessName[] = "Test process";

bool destroy_root_test() {
    BEGIN_TEST;

    mx_handle_t process;
    mx_handle_t vmar;
    ASSERT_EQ(mx_process_create(0, kProcessName, sizeof(kProcessName) - 1,
                                0, &process, &vmar), NO_ERROR, "");

    EXPECT_EQ(mx_vmar_destroy(vmar), NO_ERROR, "");

    EXPECT_EQ(mx_handle_close(vmar), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(process), NO_ERROR, "");

    END_TEST;
}

bool basic_allocate_test() {
    BEGIN_TEST;

    mx_handle_t process;
    mx_handle_t vmar;
    mx_handle_t region1, region2;
    uintptr_t region1_addr, region2_addr;

    ASSERT_EQ(mx_process_create(0, kProcessName, sizeof(kProcessName) - 1,
                                0, &process, &vmar), NO_ERROR, "");

    const size_t region1_size = PAGE_SIZE * 10;
    const size_t region2_size = PAGE_SIZE;

    // Should get an invalid args for passing a non-zero offset without
    // FLAG_SPECIFIC.
    EXPECT_EQ(mx_vmar_allocate(vmar, PAGE_SIZE, region1_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region1, reinterpret_cast<void**>(&region1_addr)),
              ERR_INVALID_ARGS, "");

    ASSERT_EQ(mx_vmar_allocate(vmar, 0, region1_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region1, reinterpret_cast<void**>(&region1_addr)),
              NO_ERROR, "");

    // Should fail since region1 does not have MX_VM_FLAG_CAN_MAP_EXECUTE
    EXPECT_EQ(mx_vmar_allocate(region1, PAGE_SIZE, region2_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_EXECUTE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              ERR_ACCESS_DENIED, "");

    ASSERT_EQ(mx_vmar_allocate(region1, 0, region2_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              NO_ERROR, "");
    EXPECT_GE(region2_addr, region1_addr, "");
    EXPECT_LE(region2_addr + region2_size, region1_addr + region1_size, "");

    EXPECT_EQ(mx_handle_close(region1), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(region2), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(vmar), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(process), NO_ERROR, "");

    END_TEST;
}

bool allocate_oob_test() {
    BEGIN_TEST;

    mx_handle_t process;
    mx_handle_t vmar;
    mx_handle_t region1, region2;
    uintptr_t region1_addr, region2_addr;

    ASSERT_EQ(mx_process_create(0, kProcessName, sizeof(kProcessName) - 1,
                                0, &process, &vmar), NO_ERROR, "");

    const size_t region1_size = PAGE_SIZE * 10;

    ASSERT_EQ(mx_vmar_allocate(vmar, 0, region1_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE |
                               MX_VM_FLAG_CAN_MAP_SPECIFIC,
                               &region1, reinterpret_cast<void**>(&region1_addr)),
              NO_ERROR, "");

    EXPECT_EQ(mx_vmar_allocate(region1, region1_size, PAGE_SIZE,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              ERR_INVALID_ARGS, "");

    EXPECT_EQ(mx_vmar_allocate(region1, region1_size - PAGE_SIZE, PAGE_SIZE * 2,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              ERR_INVALID_ARGS, "");

    EXPECT_EQ(mx_handle_close(region1), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(vmar), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(process), NO_ERROR, "");

    END_TEST;
}

bool allocate_unsatisfiable_test() {
    BEGIN_TEST;

    mx_handle_t process;
    mx_handle_t vmar;
    mx_handle_t region1, region2, region3;
    uintptr_t region1_addr, region2_addr, region3_addr;

    ASSERT_EQ(mx_process_create(0, kProcessName, sizeof(kProcessName) - 1,
                                0, &process, &vmar), NO_ERROR, "");

    const size_t region1_size = PAGE_SIZE * 10;

    ASSERT_EQ(mx_vmar_allocate(vmar, 0, region1_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE |
                               MX_VM_FLAG_CAN_MAP_SPECIFIC,
                               &region1, reinterpret_cast<void**>(&region1_addr)),
              NO_ERROR, "");

    EXPECT_EQ(mx_vmar_allocate(region1, 0, region1_size + PAGE_SIZE,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              ERR_INVALID_ARGS, "");

    // Allocate the whole range, should work
    ASSERT_EQ(mx_vmar_allocate(region1, 0, region1_size,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region2, reinterpret_cast<void**>(&region2_addr)),
              NO_ERROR, "");
    EXPECT_EQ(region2_addr, region1_addr, "");

    // Attempt to allocate a page inside of the full region
    EXPECT_EQ(mx_vmar_allocate(region1, 0, PAGE_SIZE,
                               MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE,
                               &region3, reinterpret_cast<void**>(&region3_addr)),
              ERR_NO_MEMORY, "");

    EXPECT_EQ(mx_handle_close(region2), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(region1), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(vmar), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(process), NO_ERROR, "");

    END_TEST;
}

bool nested_subregions_test() {
    BEGIN_TEST;

    mx_handle_t process;
    mx_handle_t vmar;
    ASSERT_EQ(mx_process_create(0, kProcessName, sizeof(kProcessName) - 1,
                                0, &process, &vmar), NO_ERROR, "");

    // TODO: write

    EXPECT_EQ(mx_handle_close(vmar), NO_ERROR, "");
    EXPECT_EQ(mx_handle_close(process), NO_ERROR, "");

    END_TEST;
}

// TODO: write tests that try to operate on a destroyed VMAR
// TODO: write tests that validate permissions more completely (VMO tests the
// mapping permissions work, so focus on whether or not we can successfully map
// different types)
// TODO: Destroy a VMAR and try to map where it used to be

}

BEGIN_TEST_CASE(vmar_tests)
RUN_TEST(destroy_root_test);
RUN_TEST(basic_allocate_test);
RUN_TEST(allocate_oob_test);
RUN_TEST(allocate_unsatisfiable_test);
RUN_TEST(nested_subregions_test);
END_TEST_CASE(vmar_tests)

#ifndef BUILD_COMBINED_TESTS
int main(int argc, char** argv) {
    bool success = unittest_run_all_tests(argc, argv);
    return success ? 0 : -1;
}
#endif
