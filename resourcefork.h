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
#define RF_MISSING_PATH	6
#define RF_WRITE		7

enum resource_file_flags
{
	/* Prevent the resource fork from being parsed when opened / created.
	 * This exists predominantly for the purpose of unit testing. */
	rf_no_parse = (1 << 1),

	/* Force the extended resource fork format to be used when saving the file */
	rf_save_extended = (1 << 2),
};

// MARK: - Function Declarations

/* Open a resource file, and loads into the provided `resource_file_t`.
 *
 * - Param: A refernece to a resource_file_t structure that will hold all information
 *			about the loaded resource file.
 * - Param: A set of configuration flags to influence how the resource file is loaded.
 * - Param: The path to the resource file on disk to be opended.
 *
 * - Return: A status code regarding the result of opening the resource fork. */
int resource_file_open(resource_file_t *, enum resource_file_flags, const char *restrict);

/* Create a new resource file instance in memory, using the data provided.
 * This doesn't create a resource fork on disk, but rather is used by
 * `resource_file_open(...)` to setup the `resource_file_t` instance.
 *
 * - Param: A reference to a resource_file_t structure that will hold all information
 * 			about the loaded resource file.
 * - Param:	A set of configuration flags to influence how the resource file is loaded.
 * - Param: A pointer to the raw resource fork data.
 * - Param: An indicator of how many bytes the data consists of.
 *
 * - Return: A status code regarding the result of creating the resource fork. */
int resource_file_create(resource_file_t *, enum resource_file_flags, void *restrict, ssize_t);

int resource_file_save(resource_file_t, enum resource_file_flags, const char *restrict);

/* Close and deallocate all resources related to the given resource_file_t. */
void resource_file_close(resource_file_t);

/* Free the memory used by the resource file. */
void resource_file_free(resource_file_t);


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
	uint8_t **data,
	uint64_t *size
);

int resource_file_get_resource(
	resource_file_t rf, 
	const char *type_code, 
	int64_t id, 
	const char **name,
	uint8_t **data,
	uint64_t *size
);

int resource_file_add_resource(
	resource_file_t rf,
	const char *type_code,
	int64_t id,
	const char *name,
	uint8_t *data,
	uint64_t size
);

#endif
