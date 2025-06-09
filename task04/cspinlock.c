#include <stdatomic.h>
#include <stdlib.h>
#include "cspinlock.h"

struct cspinlock {
    atomic_flag flag;
};

cspinlock_t* cspin_alloc() {
    cspinlock_t* slock = (cspinlock_t*)malloc(sizeof(cspinlock_t));
    if (slock) {
        atomic_flag_clear(&slock->flag);
    }
    return slock;
}

void cspin_free(cspinlock_t* slock) {
    free(slock);
}

int cspin_lock(cspinlock_t *slock) {
    while (atomic_flag_test_and_set(&slock->flag)) {
        // spin
    }
    return 0;
}

int cspin_trylock(cspinlock_t *slock) {
    if (!atomic_flag_test_and_set(&slock->flag)) {
        return 0; // success
    }
    return 1; // failed to acquire
}

int cspin_unlock(cspinlock_t *slock) {
    atomic_flag_clear(&slock->flag);
    return 0;
}