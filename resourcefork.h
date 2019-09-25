/*
 * Copyright (c) 2019 Tom Hancocks
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <sys/types.h>

#if !defined(libResourceFork)
#define libResourceFork

// MARK: - Forward Declarations
struct resource_file;
typedef struct resource_file *resource_file_t;

// MARK: - Constants
#define RF_OK			0
#define RF_FILE			1
#define RF_PARSE		2
#define RF_COMPRESSED	3
#define RF_TYPE 		4
#define RF_RESOURCE 	5

enum resource_file_flags
{
	// Prevent the resource fork from being parsed when opened / created.
	// This exists predominantly for the purpose of unit testing.
	rf_no_parse = (1 << 1),
};

// MARK: - Function Declarations
int resource_file_open(resource_file_t *, enum resource_file_flags, const char *restrict);
int resource_file_create(resource_file_t *, enum resource_file_flags, void *restrict, ssize_t);
void resource_file_close(resource_file_t);
void resource_file_free(resource_file_t);

int resource_file_parse(resource_file_t);

int resource_file_get_type_count(resource_file_t rf, int *count);

int resource_file_get_resource_count_idx(
	resource_file_t rf, 
	int type, 
	int *count
);

int resource_file_get_resource_count(
	resource_file_t rf, 
	const char *type_code, 
	int *count
);

int resource_file_get_type_code(
	resource_file_t rf, 
	int type, 
	const char **code
);

int resource_file_get_resource_idx(
	resource_file_t rf, 
	int type, 
	int resource, 
	int64_t *id, 
	const char **name,
	uint8_t *data,
	uint64_t *size
);

int resource_file_get_resource(
	resource_file_t rf, 
	const char *type_code, 
	int64_t id, 
	const char **name,
	uint8_t *data,
	uint64_t *size
);

#endif
