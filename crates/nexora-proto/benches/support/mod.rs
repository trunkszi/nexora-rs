use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};
struct CountingAllocator;
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
// SAFETY: Every allocation and deallocation is delegated unchanged to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller supplies the live pointer and its original layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: The caller supplies the original allocation and a valid new size.
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
pub fn zero_alloc(mut operation: impl FnMut()) {
    operation();
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    for _ in 0..100 {
        operation();
    }
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        before,
        "reusable operation allocated"
    );
}
