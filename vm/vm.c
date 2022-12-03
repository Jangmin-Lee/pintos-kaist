/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"

struct list frame_table;
struct list_elem* start;

unsigned _hash_hash_func(const struct hash_elem *p_, void *aux) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool _hash_less_func(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
    start = list_begin(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page* page = (struct page*)malloc(sizeof(struct page));

        typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
        initializerFunc initializer = NULL;

        switch(VM_TYPE(type)) {
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
		}
        uninit_new(page, upage, init, type, aux, initializer);
        page->writable = writable;
		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
    struct page* page = (struct page*)malloc(sizeof(struct page));
    struct hash_elem *e;

    page -> va = pg_round_down(va);
    e = hash_find(&spt->hash_pages, &page->hash_elem);
    free(page);

    return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	if (!hash_insert(&spt -> hash_pages, &page -> hash_elem)) {
		return true;
	}
	return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	if (!hash_delete(&spt -> hash_pages, &page -> hash_elem)) {
		return true;
	}
	return false;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
    struct thread *curr = thread_current();
    struct list_elem *e = start;

    for (start = e; start != list_end(&frame_table); start = list_next(start)) {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr -> pml4, victim -> page -> va)) {
            pml4_set_accessed (curr -> pml4, victim -> page -> va, 0);
		} else {
            return victim;
		}
    }

    for (start = list_begin(&frame_table); start != e; start = list_next(start)) {
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr -> pml4, victim -> page -> va)) {
            pml4_set_accessed (curr -> pml4, victim -> page -> va, 0);
		} else {
            return victim;
		}
    }
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
    swap_out(victim->page);

    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));

	void * newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL)
    {
        frame = vm_evict_frame();
        frame -> page = NULL;
        return frame;
    }
	frame -> kva = newpage;
    list_push_back (&frame_table, &frame -> frame_elem);
    frame -> page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame -> page == NULL);
	return frame;
}

/* Growing the stack. */
static bool
vm_stack_growth (void *addr) {
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true))
    {
        thread_current() -> stack_bottom -= PGSIZE;
		return true;
    }
	return false;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page) {
}

/* Return true on success */
bool
vm_try_handle_fault (
	struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (!addr || is_kernel_vaddr(addr)) {
        return false;
	}

	page = spt_find_page(spt, addr);

	if (!page)
	{
		void *rsp_ptr = is_kernel_vaddr(f -> rsp) ? thread_current() -> handler_rsp : f -> rsp;

		if (addr >= USER_STACK - (1 << 20) && USER_STACK > addr && addr >= rsp_ptr - 8)
		{
			void *fpage = thread_current() -> stack_bottom - PGSIZE;
			if (vm_stack_growth(fpage)) {
				page = spt_find_page(spt, fpage);
			}
			else {
				return false;
			}
		}
		else {
			return false;
		}
	}
	return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	page = spt_find_page(&thread_current()->spt, va);

	if (page == NULL) {
		return false;
	}

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *curr = thread_current();

	if (pml4_get_page (curr -> pml4, page -> va) == NULL \
		&& pml4_set_page (curr -> pml4, page -> va, frame -> kva, page -> writable)) {

        return swap_in(page, frame->kva);
    }
    return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	bool res = hash_init(&spt->hash_pages, _hash_hash_func, _hash_less_func, NULL);
	if (res == false) {
		exit(-1);
	}
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {

    struct hash_iterator i;
	bool success = false;
	struct thread *curr = thread_current();

    hash_first (&i, &src -> hash_pages);

    while (hash_next (&i)) {
        struct page *parent_page = hash_entry (hash_cur (&i), struct page, hash_elem);
		success = vm_alloc_page_with_initializer(
			parent_page->uninit.type,
			parent_page->va,
			parent_page->writable,
			parent_page->uninit.init,
			parent_page->uninit.aux);
		struct page *child_page = spt_find_page(&curr->spt, parent_page->va);
		if (parent_page->frame)
		{
			success = vm_do_claim_page(child_page);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
    }
    return success;
}

void page_free(struct hash_elem *e, void* aux) {
    const struct page *page = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
    hash_destroy(&spt->hash_pages, page_free);
}
