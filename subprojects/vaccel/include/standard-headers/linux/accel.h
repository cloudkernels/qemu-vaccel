#ifndef _ACCEL_H
#define _ACCEL_H

#include "standard-headers/linux/types.h"

#define TIMERS_NAME_MAX 64

/* IOCTLs */
#define VACCEL_SESS_CREATE      _IOWR('@', 0, struct accel_session)
#define VACCEL_SESS_DESTROY     _IOWR('@', 1, struct accel_session)
#define VACCEL_DO_OP            _IOWR('@', 2, struct accel_session)
#define VACCEL_GET_TIMERS       _IOWR('@', 3, struct accel_session)


struct accel_arg {
	uint32_t len;
	unsigned char *buf;
};

struct accel_op {
	/* Number of in arguments */
	uint32_t in_nr;

	/* Pointer to in arguments */
	struct accel_arg *in;

	/* Number of out arguments */
	uint32_t out_nr;

	/* Pointer to out arguments */
	struct accel_arg *out;
};

struct accel_session {
	/* Session id */
	uint32_t id;

	/* Operation performed currently */
	struct accel_op op;
};

struct accel_prof_sample {
	/* Timestamp (nsec) of entering the region */
	uint64_t start;

	/* Time (nsec) elapsed inside the region */
	uint64_t time;
};

struct accel_prof_region {
	/* Name of the region */
	char name[TIMERS_NAME_MAX];

	/* Number of collected samples */
	uint64_t nr_entries;

	/* Array of collected samples */
	struct accel_prof_sample *samples;

	/* Allocated size for the array */
	uint64_t size;
};

#endif /* _ACCEL_H */
