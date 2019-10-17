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

#include "resourcefork.h"
#include <libEncoding/macroman.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// MARK: - Global Variables

char rf_error[1024] = {0};

#if defined(DEBUG_TEST)
int main(int argc, const char **argv)
{
	resource_file_t rf = NULL;
	if (resource_file_open(&rf, 0, argv[1]) != RF_OK) {
		printf("%s\n", rf_error);
	} else {
		// resource_file_save(rf, 0, "/tmp/test-save.rsrc");
		resource_file_close(rf);
	}
	return 0;
}
#endif

// MARK: - ResourceFork Constants

#define STANDARD_RESOURCE_TYPE_LENGTH	(8L)
#define EXTENDED_RESOURCE_TYPE_LENGTH	(20L)
#define STANDARD_RESOURCE_LENGTH		(12L)
#define EXTENDED_RESOURCE_LENGTH		(29L)

// MARK: - ResourceFork Data Structures

enum resource_fork_type
{
	resource_fork_standard,
	resource_fork_extended,
};

struct resource_fork_preamble 
{
	uint64_t data_offset;
	uint64_t map_offset;
	uint64_t data_size;
	uint64_t map_size;
} __attribute__((packed));

struct resource_fork_map 
{
	uint16_t flags;
	uint64_t type_list_offset;
	uint64_t name_list_offset;
};

struct resource_type 
{
	const char *code;
	uint64_t resource_count;
	uint64_t resource_offset;
	uint64_t resource_index;
};

struct resource 
{
	int64_t id;
	const char *name;
	uint8_t flags;
	uint64_t data_offset;
	uint64_t data_size;
	void *data;
};

struct resource_fork 
{
	struct resource_fork_preamble preamble;
	struct resource_fork_map map;
	uint64_t type_count;
	uint64_t resource_count;
	struct resource_type *types;
	struct resource *resources;
};

struct data_buffer 
{
	uint8_t *data;
	ssize_t size;
	off_t pos;
};

struct resource_file {
	enum resource_fork_type type;
	const char *path;
	struct data_buffer *handle;
	struct resource_fork rsrc;
};

// MARK: - Data Buffer

static inline int buffer_eof(struct data_buffer *restrict stream)
{
	if (!stream) {
		return 0;
	}
	return (stream->pos >= stream->size);
}

static inline void buffer_seek(struct data_buffer *stream, long offset, int whence)
{
	if (!stream) {
		return;
	}

	switch (whence) {
		case SEEK_SET:
			stream->pos = offset;
			break;
		case SEEK_CUR:
			stream->pos += offset;
			break;
		case SEEK_END:
			stream->pos = stream->size - 1 - offset;
			break;
		default:
			break;
	}
}

static inline long buffer_tell(struct data_buffer *restrict stream)
{
	return stream ? stream->pos : 0;
}

#define F_NONE		0x0
#define F_ENDIAN 	0x1

size_t buffer_read_flags(
	void *restrict ptr, 
	size_t size, 
	size_t nitems,
	int flags,
	struct data_buffer *restrict stream
) {
	if (!stream) {
		return 0;
	}
	
	size_t count = 0;
	while (!buffer_eof(stream) && nitems--) {
		// Get a representation that we can work with easily.
		uint8_t *p = (uint8_t *)ptr;
		uint8_t *pp = (uint8_t *)ptr;
		for (int len = 0; len < size && stream->pos < stream->size; ++len) {		
			*pp++ = stream->data[stream->pos++];
		}

		// Perform the big endian swap. However this is only done
		// on integer values (2, 3, 4 & 8 bytes).
		if ((flags & F_ENDIAN) && ((size >= 2 && size <= 4) || size == 8)) {
			for (int i = 0; i < (size >> 1); ++i) {
				uint8_t tmp = p[size - 1 - i];
				p[size - 1 - i] = p[i];
				p[i] = tmp;
			}
		}	

		// Advance to the next memory location.
		ptr = (void *)((uintptr_t)ptr + size);
		count++;
	}

	// Return the number of items read.
	return count;
}

size_t buffer_read(
	void *restrict ptr, 
	size_t size, 
	size_t nitems,
	struct data_buffer *restrict stream
) {
	return buffer_read_flags(ptr, size, nitems, F_ENDIAN, stream);
}

// MARK: - ResourceFork Loading

int resource_file_parse(resource_file_t);

int resource_file_open(resource_file_t *rf, enum resource_file_flags flags, const char *restrict path)
{
	int err = 0;
	assert(rf != NULL);

	// Try and open the file. No point starting allocations if
	// the file is bad.
	FILE *handle = fopen(path, "r");
	if (handle == NULL) {
		snprintf(rf_error, sizeof(rf_error),
			"resource_file_open failed to open '%s'",
			path);
		return RF_FILE;
	}

	// Load the contents of the file in to the buffer.
	fseek(handle, 0L, SEEK_END);
	ssize_t size = ftell(handle);
	void *data = calloc(1, size);
	fseek(handle, 0L, SEEK_SET);

	if (fread(data, 1, size, handle) != size) {
		fclose(handle);
		resource_file_free(*rf);
		return RF_FILE;
	}

	fclose(handle);

	// Parse and load the resource fork.
	if ((err = resource_file_create(rf, flags, data, size)) != RF_OK) {
		return err;
	}

	// Make sure the path is copied into the resource file instance.
	(*rf)->path = calloc(strlen(path) + 1, 1);
	strncpy((void *)(*rf)->path, path, strlen(path));
	return err;
}

int resource_file_create(resource_file_t *rf, enum resource_file_flags flags,  void *restrict data, ssize_t size)
{
	int err = 0;
	assert(rf != NULL);

	// Setup a data buffer to represent and contain the data.
	struct data_buffer *buffer = calloc(1, sizeof(*buffer));
	buffer->data = data;
	buffer->size = size;
	buffer->pos = 0;

	// File is open and known good. Start setting up the structure
	// and allocations.
	*rf = calloc(1, sizeof(**rf));
	(*rf)->handle = buffer;

	// A major part of opening the file is parsing the resource map.
	// If the resource map is invalid, then we can infer that the
	// file is not a resource file and thus should be ignored.
	if (!(flags & rf_no_parse) && data != NULL && size > 0) {
		if ((err = resource_file_parse(*rf)) != RF_OK) {
			goto RSRC_PARSE_ERROR;
		}	
	}

	// Successfully completed opening the resource fork.
	return RF_OK;

RSRC_PARSE_ERROR:
	// Clean up and make sure we're not leaking memory!
	resource_file_free(*rf);
	return RF_PARSE;
}

// MARK: - Resource File Deallocation

void resource_file_close(resource_file_t rf)
{
	if (rf) {
#if defined(DEBUG_TEST)
		printf("closing resource fork...\n");
#endif
		if (rf->handle) {
			free((void *)rf->handle->data);
		}
		free((void *)rf->handle);

		// Step through each of the resources and free any allocated data pointers
		// and names, before freeing the resources themselves.
		for (int i = 0; i < rf->rsrc.resource_count; ++i) {
#if defined(DEBUG_TEST)
			printf("releasing resource %d '%s' data and name.\n", i, rf->rsrc.resources[i].name);
#endif
			free((void *)rf->rsrc.resources[i].data);
			free((void *)rf->rsrc.resources[i].name);
		}
		free((void *)rf->rsrc.resources);

		// Repeat the same for types. Free any type codes, and then free the types
		// themselves
		for (int i = 0; i <= rf->rsrc.type_count; ++i) {
#if defined(DEBUG_TEST)
			printf("releasing type %d '%s'\n", i, rf->rsrc.types[i].code);
#endif
			free((void *)rf->rsrc.types[i].code);
		}
		free((void *)rf->rsrc.types);
	}
}

void resource_file_free(resource_file_t rf)
{
	resource_file_close(rf);
	free((void *)rf->path);
	free(rf);
}

// MARK: - ResourceFork Parsing Base

int resource_file_parse_preamble(
	resource_file_t rf,
	struct resource_fork_preamble *preamble
) {
	// The preamble is located at the very start of the file, so ensure that
	// is where we are located.
	buffer_seek(rf->handle, 0L, SEEK_SET);

	// The first thing that needs to be done is to determine the type of resource
	// fork that we're dealing with. To do this read out a 64-bit value and check
	// its value. If the value is anything other than 1, then we know we are dealing
	// with a standard resource fork.
	uint64_t format_version = 0;
	buffer_read(&format_version, sizeof(uint64_t), 1, rf->handle);

	if (format_version == 1) {

#if defined(DEBUG_TEST)
		printf("Reading an Extended ResourceFork\n");
#endif

		// We're dealing with the extended ResourceFork, load the rest of the
		// preamble as 64-bit integers
		rf->type = resource_fork_extended;

		uint64_t preamble_values[4] = { 0 };
		buffer_read(preamble_values, sizeof(uint64_t), 4, rf->handle);

		preamble->data_offset = preamble_values[0];
		preamble->map_offset = preamble_values[1];
		preamble->data_size = preamble_values[2];
		preamble->map_size = preamble_values[3];
	}
	else {

#if defined(DEBUG_TEST)
		printf("Reading an Standard ResourceFork\n");
#endif

		// It is a standard resource fork. Load the preamble acording to spec.
		rf->type = resource_fork_standard;

		uint32_t preamble_values[4] = { 0 };
		buffer_seek(rf->handle, 0L, SEEK_SET);
		buffer_read(preamble_values, sizeof(uint32_t), 4, rf->handle);

		preamble->data_offset = (uint64_t)preamble_values[0];
		preamble->map_offset = (uint64_t)preamble_values[1];
		preamble->data_size = (uint64_t)preamble_values[2];
		preamble->map_size = (uint64_t)preamble_values[3];
	}

#if defined(DEBUG_TEST)
	printf("data_offset: %016llx\n", preamble->data_offset);
	printf("map_offset: %016llx\n", preamble->map_offset);
	printf("data_size: %lld\n", preamble->data_size);
	printf("map_size: %lld\n", preamble->map_size);
#endif

	// There isn't really a check that we can do here to ensure the validity of the values
	// read, but we can do some arithematic tests to see if the values make sense.
	// 
	// TODO: Validate the values to make sure they make sense.
	//

	return RF_OK;
}

int resource_file_parse_map(
	resource_file_t rf
) {
	// Jump to the start of the resource map. The start of the map has a copy of the preamble,
	// which we can use as a "validation/checksum" for the resource file "integrity".
	struct resource_fork_preamble chk_preamble = { 0 };
	buffer_seek(rf->handle, rf->rsrc.preamble.map_offset, SEEK_SET);

	if (rf->type == resource_fork_extended) {
		uint64_t preamble_values[4] = { 0 };
		if (buffer_read(preamble_values, sizeof(uint64_t), 4, rf->handle) != 4) {
			snprintf(rf_error, sizeof(rf_error),
			"Error validating and checking resource fork preamble.");
			return RF_PARSE;
		}

		chk_preamble.data_offset = preamble_values[0];
		chk_preamble.map_offset = preamble_values[1];
		chk_preamble.data_size = preamble_values[2];
		chk_preamble.map_size = preamble_values[3];
	}
	else {
		uint32_t preamble_values[4] = { 0 };
		if (buffer_read(preamble_values, sizeof(uint32_t), 4, rf->handle) != 4) {
			snprintf(rf_error, sizeof(rf_error),
			"Error validating and checking resource fork preamble.");
			return RF_PARSE;
		}

		chk_preamble.data_offset = preamble_values[0];
		chk_preamble.map_offset = preamble_values[1];
		chk_preamble.data_size = preamble_values[2];
		chk_preamble.map_size = preamble_values[3];
	}

	if (
		(chk_preamble.data_offset != rf->rsrc.preamble.data_offset) &&
		(chk_preamble.map_offset != rf->rsrc.preamble.map_offset) &&
		(chk_preamble.data_size != rf->rsrc.preamble.data_size) &&
		(chk_preamble.map_size != rf->rsrc.preamble.map_size)
	) {
		snprintf(rf_error, sizeof(rf_error),
			"Error validating and checking resource fork preamble.");
		return RF_PARSE;
	}

#if defined(DEBUG_TEST)
	printf("confirmed resource fork preamble.\n");
#endif

	// After confirming the preamble, we can be sure that what we are reading is a resource
	// fork. Continue reading and parsing the resource map.
	// The immediate structure of the map is as such:
	// 
	// 		Size		Purpose
	// 		----------------------------------------
	// 		6 bytes		Unknown / Unused
	// 		2 bytes		ResourceFork flags
	// 		2 bytes		Resource Type List offset
	// 		2 bytes		Resource Name List offset
	//
	buffer_seek(rf->handle, 6L, SEEK_CUR);
	
	if (buffer_read(&rf->rsrc.map.flags, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork flags.");
		return RF_PARSE;
	}

	if (rf->type == resource_fork_extended) {
		// In the extended resource fork the offsets here are 8 bytes long 
		// (64-bit values).
		if (buffer_read(&rf->rsrc.map.type_list_offset, sizeof(uint64_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork type list offset.");
			return RF_PARSE;
		}
	
		if (buffer_read(&rf->rsrc.map.name_list_offset, sizeof(uint64_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork name list offset.");
			return RF_PARSE;
		}
	}
	else {
		// The standard resource fork is according to the spec and information
		// listed above. However due to the actual storage of these values being
		// increased to accomodate the extended resources, we need to read into
		// a seperate variable first.
		uint16_t tmp = 0;
		if (buffer_read(&tmp, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork type list offset.");
			return RF_PARSE;
		}
		rf->rsrc.map.type_list_offset = tmp;
	
		if (buffer_read(&tmp, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork name list offset.");
			return RF_PARSE;
		}
		rf->rsrc.map.name_list_offset = tmp;
	}

	// For now we are not handling compressed resource forks. Check for compression and if
	// present then raise an error.
	if (rf->rsrc.map.flags & 0x0040) {
		// Compression is turned on in the ResourceFork.
		// TODO: Implement a decompression handler.
		snprintf(rf_error, sizeof(rf_error), "Unable to handle resource fork compression.");
		return RF_COMPRESSED;
	}
	
	// We have successfully determined the layout of the resource fork.
#if defined(DEBUG_TEST)
	printf("finished parsing the basic resource fork map.\n");
#endif
	return RF_OK;
}

int resource_file_parse_types(
	resource_file_t rf
) {
	uint16_t tmp = 0;

	// The first job is to seek to the appropriate location in the file.
	buffer_seek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.type_list_offset, SEEK_SET);

	// The first value that we need to read tells us how many resource types exist within
	// the resource fork. This will tell us how large the `types` array needs to be, and
	// how many types we need to parse.
	if (rf->type == resource_fork_extended) {
		if (buffer_read(&rf->rsrc.type_count, sizeof(uint64_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to determine number of resource types.");
			return RF_PARSE;
		}
	}
	else {
		if (buffer_read(&tmp, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to determine number of resource types.");
			return RF_PARSE;
		}
		rf->rsrc.type_count = tmp;
	}
	

	// Allocate the memory needed to store the type information.
	rf->rsrc.types = calloc(rf->rsrc.type_count + 1, sizeof(*rf->rsrc.types));
	
	// Now parse out each of the resource types
	for (uint64_t i = 0; i <= rf->rsrc.type_count; ++i) {
		// The resource type code is the first thing to be read. This is 4 bytes long, and is
		// _not_ endian specific. The type code remains the same in the extended format.
		int n = 0;
		char raw_code[4] = { 0 };
		if ((n = buffer_read_flags(raw_code, 1, 4, F_NONE, rf->handle)) != 4) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource type code (%d).", n);
			return RF_PARSE;
		}
		rf->rsrc.types[i].code = utf8_from_macroman(raw_code, 4);

		// The next two values are endian specific, and vary depending on the file
		// being an extended or standard resource fork.
		if (rf->type == resource_fork_extended) {
			if (buffer_read(&rf->rsrc.types[i].resource_count, sizeof(uint64_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource count for type.");
				return RF_PARSE;
			}
	
			if (buffer_read(&rf->rsrc.types[i].resource_offset, sizeof(uint64_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource offset for type.");
				return RF_PARSE;
			}
		}
		else {
			if (buffer_read(&tmp, sizeof(uint16_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource count for type.");
				return RF_PARSE;
			}
			rf->rsrc.types[i].resource_count = tmp;
	
			if (buffer_read(&tmp, sizeof(uint16_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource offset for type.");
				return RF_PARSE;
			}
			rf->rsrc.types[i].resource_offset = tmp;
		}
		

#if defined(DEBUG_TEST)
		// Display some information about the resource type.
		printf("%lld '%s' %lld resource(s), offset: %#016llx\n",
				i, rf->rsrc.types[i].code,
				rf->rsrc.types[i].resource_count + 1, rf->rsrc.types[i].resource_offset);
#endif
	}
	
	// We have completed successfully.
	return RF_OK;
}

int resource_file_parse_resources(
	resource_file_t rf
) {
	uint16_t tmp = 0;
	
	// Before anything else is even attempted, we need to know how many resources
	// there are in the resource fork in total. To do this we can add up all of the resource
	// counts in each of the types.
	rf->rsrc.resource_count = 0;
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		rf->rsrc.resource_count += rf->rsrc.types[i].resource_count + 1;
	}

#if defined(DEBUG_TEST)
	printf("there are %lld resources in the resource fork.\n", rf->rsrc.resource_count);
#endif

	// Allocate the required space for the resources.
	rf->rsrc.resources = calloc(rf->rsrc.resource_count + 1, sizeof(*rf->rsrc.resources));

	// Move to the appropriate location in the file, and begin loading the resources.
	int index_offset = 0;
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		int offset = rf->rsrc.types[i].resource_offset;
		buffer_seek(rf->handle, 
			  rf->rsrc.preamble.map_offset + rf->rsrc.map.type_list_offset + offset, 
			  SEEK_SET);

		// Update the initial resource index in the type structure for quick lookup
		// later.
		rf->rsrc.types[i].resource_index = index_offset;

		// Read each of the resources. This involves parsing out the appropriate data
		// and inserting it into each of the allocated resource records.
		// Most values here are altered, in the extended resource fork, so this is implemented
		// as two seperate loops for performance reasons.
		if (rf->type == resource_fork_extended) {
			for (uint64_t j = index_offset, k = 0; k <= rf->rsrc.types[i].resource_count; ++k, ++j, ++index_offset) {
				if (buffer_read(&rf->rsrc.resources[j].id, sizeof(int64_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource id.");
					return RF_PARSE;
				}
				
				uint64_t name_offset = 0;
				if (buffer_read(&name_offset, sizeof(uint64_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource name offset.");
					return RF_PARSE;
				}
	
				if (buffer_read(&rf->rsrc.resources[j].flags, 1, 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource flags.");
					return RF_PARSE;
				}
	
				if (buffer_read(&rf->rsrc.resources[j].data_offset, sizeof(uint64_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource data offset.");
					return RF_PARSE;
				}
				
				// Now that all of the resource fields have been extracted, find and parse the name
				// of the resource. However if the name offset is 0xFFFFFFFFFFFFFFFF, then we know 
				// there is no name assigned.
				if (name_offset != UINT64_MAX) {
					long cur_pos = buffer_tell(rf->handle);
					buffer_seek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.name_list_offset + name_offset, SEEK_SET);
				
					uint8_t name_length = 0;
					if (buffer_read(&name_length, 1, 1, rf->handle) != 1) {
						snprintf(rf_error, sizeof(rf_error), "Failed to determine the length of the resource name.");
						return RF_PARSE;
					}
	
					char raw_name[256] = { 0 };
					if (buffer_read_flags(&raw_name, 1, name_length, F_NONE, rf->handle) != name_length) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read the resource name.");
						return RF_PARSE;
					}
	
					rf->rsrc.resources[j].name = utf8_from_macroman(raw_name, name_length);
					buffer_seek(rf->handle, cur_pos, SEEK_SET);
				}
	
				// Finally try to load the data into memory for the resource.
				// NOTE: Due to the format supporting 16EiB of data per resource,
				// this should be converted to a memory mapped allocation so the
				// data remains on disk until needed - however it's unlikely to
				// be a problem for now.
				//
				// ☠️
				{
					// Seek to the beginning of the data and query the length of the
					// data.
					long cur_pos = buffer_tell(rf->handle);
					buffer_seek(
						rf->handle, 
						rf->rsrc.resources[j].data_offset + rf->rsrc.preamble.data_offset, 
						SEEK_SET
					);
		
					uint64_t data_size = 0;
					if (buffer_read(&data_size, sizeof(uint64_t), 1, rf->handle) != 1) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read resource data size.");
						return RF_PARSE;
					}
					rf->rsrc.resources[j].data_size = data_size;
	
					rf->rsrc.resources[j].data = malloc(rf->rsrc.resources[j].data_size);
					if (buffer_read_flags(
						rf->rsrc.resources[j].data, 
						1, rf->rsrc.resources[j].data_size, 
						F_NONE, rf->handle
					) != rf->rsrc.resources[j].data_size) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read resource data.");
						return RF_PARSE;
					}
	
					// Restore the old position.
					buffer_seek(rf->handle, cur_pos, SEEK_SET);
				}

				#if defined(DEBUG_TEST)
				printf("  '%s' %lld: %s (%#016llx) [%lld/%lld] {%lld bytes}\n", 
						rf->rsrc.types[i].code, rf->rsrc.resources[j].id, 
						rf->rsrc.resources[j].name, rf->rsrc.resources[j].data_offset,
						j, rf->rsrc.resource_count, rf->rsrc.resources[j].data_size);
				#endif	
	
				// Skip over the next 4 bytes.
				buffer_seek(rf->handle, 4L, SEEK_CUR);
			}

		}
		else {
			for (uint64_t j = index_offset, k = 0; k <= rf->rsrc.types[i].resource_count; ++k, ++j, ++index_offset) {
				if (buffer_read(&tmp, sizeof(int16_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource id.");
					return RF_PARSE;
				}
				rf->rsrc.resources[j].id = (int16_t)tmp;
				
				uint16_t name_offset = 0;
				if (buffer_read(&name_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource name offset.");
					return RF_PARSE;
				}
	
				if (buffer_read(&rf->rsrc.resources[j].flags, 1, 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource flags.");
					return RF_PARSE;
				}
	
				uint8_t offset_raw[3] = { 0 };
				if (buffer_read(offset_raw, sizeof(offset_raw), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource data offset.");
					return RF_PARSE;
				}
				rf->rsrc.resources[j].data_offset = (offset_raw[2] << 16) | (offset_raw[1] << 8) | (offset_raw[0]);
				
				// Now that all of the resource fields have been extracted, find and parse the name
				// of the resource. However if the name offset is 0xFFFF, then we know there is no
				// name assigned.
				if (name_offset != UINT16_MAX) {
					long cur_pos = buffer_tell(rf->handle);
					buffer_seek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.name_list_offset + name_offset, SEEK_SET);
				
					uint8_t name_length = 0;
					if (buffer_read(&name_length, 1, 1, rf->handle) != 1) {
						snprintf(rf_error, sizeof(rf_error), "Failed to determine the length of the resource name.");
						return RF_PARSE;
					}
	
					char raw_name[256] = { 0 };
					if (buffer_read_flags(&raw_name, 1, name_length, F_NONE, rf->handle) != name_length) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read the resource name.");
						return RF_PARSE;
					}
	
					rf->rsrc.resources[j].name = utf8_from_macroman(raw_name, name_length);
					buffer_seek(rf->handle, cur_pos, SEEK_SET);
				}
	
				// Finally try to load the data into memory for the resource.
				{
					// Seek to the beginning of the data and query the length of the
					// data.
					long cur_pos = buffer_tell(rf->handle);
					buffer_seek(
						rf->handle, 
						rf->rsrc.resources[j].data_offset + rf->rsrc.preamble.data_offset, 
						SEEK_SET
					);
		
					uint32_t data_size = 0;
					if (buffer_read(&data_size, sizeof(uint32_t), 1, rf->handle) != 1) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read resource data size.");
						return RF_PARSE;
					}
					rf->rsrc.resources[j].data_size = data_size;
	
					rf->rsrc.resources[j].data = malloc(rf->rsrc.resources[j].data_size);
					if (buffer_read_flags(
						rf->rsrc.resources[j].data, 
						1, rf->rsrc.resources[j].data_size, 
						F_NONE, rf->handle
					) != rf->rsrc.resources[j].data_size) {
						snprintf(rf_error, sizeof(rf_error), "Failed to read resource data.");
						return RF_PARSE;
					}
	
					// Restore the old position.
					buffer_seek(rf->handle, cur_pos, SEEK_SET);
				}

				#if defined(DEBUG_TEST)
				printf("  '%s' %lld: %s (%#016llx) [%lld/%lld] {%lld bytes}\n", 
						rf->rsrc.types[i].code, rf->rsrc.resources[j].id, 
						rf->rsrc.resources[j].name, rf->rsrc.resources[j].data_offset,
						j, rf->rsrc.resource_count, rf->rsrc.resources[j].data_size);
				#endif	
	
				// Skip over the next 4 bytes.
				buffer_seek(rf->handle, 4L, SEEK_CUR);
			}
		}
		
	}	

	return RF_OK;
}

int resource_file_parse(resource_file_t rf)
{
	int err = 0;

#if defined(DEBUG_TEST)
	printf("preparing to parse resource file...\n");
#endif

	// Parse the Resource Fork preamble. This describes where each
	// of the segments are, and how large they are. Without this,
	// we can not proceed.
	if ((err = resource_file_parse_preamble(rf, &rf->rsrc.preamble)) != RF_OK) {
		goto RSRC_PARSE_ERROR;
	}

	// Parse the Resource Fork map, types and resources.
	if ((err = resource_file_parse_map(rf)) != RF_OK) {
		goto RSRC_PARSE_ERROR;
	}

	if ((err = resource_file_parse_types(rf)) != RF_OK) {
		goto RSRC_PARSE_ERROR;
	}

	if ((err = resource_file_parse_resources(rf)) != RF_OK) {
		goto RSRC_PARSE_ERROR;
	}

	return RF_OK;
	
RSRC_PARSE_ERROR:
	return RF_PARSE;	
}

// MARK: - Resource Fork Look Up

int resource_file_get_type_count(resource_file_t rf, int *count)
{
	if (count) {
		*count = (int)rf->rsrc.type_count + 1;
	}
	return RF_OK;
}

int resource_file_get_resource_count_idx(resource_file_t rf, int type, int *count)
{
	// Fetch the actual resource type record.
	struct resource_type *type_ptr = &rf->rsrc.types[type];
	if (count) {
		*count = (int)type_ptr->resource_count + 1;
	}
	return RF_OK;
}

int resource_file_get_resource_count(
	resource_file_t rf, 
	const char *type_code, 
	int *count
) {
	// Determine the index of the type given the code provided.
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		struct resource_type *type_ptr = &rf->rsrc.types[i];
		if (strcmp(type_ptr->code, type_code) == 0) {
			if (count) {
				*count = (int)type_ptr->resource_count + 1;
			}
			return RF_OK;
		}
	}
	return RF_TYPE;
}

int resource_file_get_type_code(resource_file_t rf, int type, const char **code)
{
	struct resource_type *type_ptr = &rf->rsrc.types[type];
	if (code) {
		*code = type_ptr->code;
	}
	return RF_OK;
}

int resource_file_get_resource_idx(
	resource_file_t rf, 
	int type, 
	int resource, 
	int64_t *id, 
	const char **name,
	uint8_t **data,
	uint64_t *size
) {
	// Look up the type and then handle the resource index offset.
	struct resource_type *type_ptr = &rf->rsrc.types[type];
	resource += type_ptr->resource_index;

	// Look up the actual resource instance now
	struct resource *resource_ptr = &rf->rsrc.resources[resource];

	if (id) {
		*id = resource_ptr->id;
	}

	if (*name) {
		*name = resource_ptr->name;
	}

	return RF_OK;
}

int resource_file_get_resource(
	resource_file_t rf, 
	const char *type_code, 
	int64_t id, 
	const char **name,
	uint8_t **data,
	uint64_t *size
) {
	struct resource_type *type_ptr = NULL;
	struct resource *resource_ptr = NULL;
	for (int type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		if (strcmp(type_ptr->code, type_code) == 0) {
			goto RESOURCE_TYPE_FOUND;
		}
	}
	return RF_TYPE;

RESOURCE_TYPE_FOUND:
	for (int res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
		resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];
		if (resource_ptr->id == id) {
			goto RESOURCE_FOUND;
		}
	}
	return RF_RESOURCE;

RESOURCE_FOUND:
	if (name) {
		*name = resource_ptr->name;
	}

	if (data) {
		*data = resource_ptr->data;
	}

	if (size) {
		*size = resource_ptr->data_size;
	}

	return RF_OK;
}

int resource_file_add_resource(
	resource_file_t rf,
	const char *type_code,
	int64_t id,
	const char *name,
	uint8_t *data,
	uint64_t size
) {
	assert(rf != NULL);

	// Do we already have a container for the type?
	struct resource_type *type_ptr = NULL;
	for (int type_idx = 0; rf->rsrc.types && type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		if (strcmp(type_ptr->code, type_code) == 0) {
			goto RESOURCE_TYPE_FOUND;
		}
	}

	// We do not and thus need to create a new type. Expand the allocation
	// space for a new type.
    if (rf->rsrc.types) {
        rf->rsrc.type_count++;
        rf->rsrc.types = realloc(rf->rsrc.types, (rf->rsrc.type_count + 1) * sizeof(*rf->rsrc.types));
    } else {
        rf->rsrc.types = calloc(rf->rsrc.type_count + 1, sizeof(*rf->rsrc.types));
    }

	size_t type_code_len = strlen(type_code);
	type_ptr = &rf->rsrc.types[rf->rsrc.type_count];
	type_ptr->code = calloc(type_code_len + 1, 1);
	strncpy((void *)type_ptr->code, type_code, type_code_len);

	type_ptr->resource_offset = 0;
	type_ptr->resource_count = 0xFFFFFFFFFFFFFFFF; // Indicate that we'll be adding the first value.
	type_ptr->resource_index = rf->rsrc.resource_count; // The next available index is at the end of the list.

RESOURCE_TYPE_FOUND:
	
	// TODO: We _should_ check that there isn't already an existing resource
	// with this ID.
    if (rf->rsrc.resources) {
        rf->rsrc.resource_count++;
        size_t resources_size = (rf->rsrc.resource_count + 1) * sizeof(*rf->rsrc.resources);
        rf->rsrc.resources = realloc(rf->rsrc.resources, resources_size);
    } else {
        rf->rsrc.resources = calloc(rf->rsrc.resource_count + 1, sizeof(*rf->rsrc.resources));
    }

	
	struct resource *resource_ptr = NULL;
	if (type_ptr->resource_count == 0xFFFFFFFFFFFFFFFF) {
		// Brand new resource type... We can just a new resource to the end of
		// list.
		resource_ptr = &rf->rsrc.resources[rf->rsrc.resource_count];
		type_ptr->resource_count = 0;
	}
	else {
		// Existing resource type... We need to modify the resource list and
		// inject a new resource into the middle of it.
		// Insert the new resource at the start of the resources for the type.
		uintptr_t offset = type_ptr->resource_index;
		size_t size = (rf->rsrc.resource_count + 1 - offset) * sizeof(*rf->rsrc.resources); 
		memmove(rf->rsrc.resources + offset, rf->rsrc.resources + offset + 1, size);

		type_ptr->resource_count++;
	}

	// Fill out information for the resource itself.
	resource_ptr->id = id;
    resource_ptr->name = NULL;
	resource_ptr->flags = 0;
	resource_ptr->data = data;
	resource_ptr->data_size = size;

    // Allocate space for the name and copy it in.
    if (name) {
        size_t name_len = strlen(name);
        resource_ptr->name = calloc(name_len + 1, 1);
        memcpy((char *)resource_ptr->name, name, name_len);
    }

	return RF_OK;
}


// MARK: - Resource File Saving

size_t file_write_flags(
	void *restrict ptr, 
	size_t size, 
	size_t nitems,
	int flags,
	FILE *stream
) {
	if (!stream) {
		return 0;
	}

	// Create a buffer that is long enough to hold a single item.
	uint8_t *buffer = malloc(size);
	
	size_t count = 0;
	while (nitems--) {
		// Get a representation that we can work with easily.
		uint8_t *p = (uint8_t *)ptr;
		uint8_t *pp = (uint8_t *)buffer;
		for (int len = 0; len < size; ++len) {		
			*pp++ = *p++;
		}

		// Perform the big endian swap. However this is only done
		// on integer values (2, 3, 4 & 8 bytes).
		if ((flags & F_ENDIAN) && ((size >= 2 && size <= 4) || size == 8)) {
			for (int i = 0; i < (size >> 1); ++i) {
				uint8_t tmp = buffer[size - 1 - i];
				buffer[size - 1 - i] = buffer[i];
				buffer[i] = tmp;
			}
		}

		// Write the buffer to the file.
		if (fwrite(buffer, size, 1, stream) != 1) {
			free(buffer);
			return count;
		}

		// Advance to the next memory location.
		ptr = (void *)((uintptr_t)ptr + size);
		count++;
	}

	// Return the number of items read.
	free(buffer);
	return count;
}

size_t file_write(
	void *restrict ptr, 
	size_t size, 
	size_t nitems,
	FILE *stream
) {
	return file_write_flags(ptr, size, nitems, F_ENDIAN, stream);
}

size_t file_pad(
	uint8_t value,
	size_t nitems,
	FILE *stream
) {
	size_t count = 0;
	for (int i = 0; i < nitems; ++i) {
		count += file_write(&value, 1, 1, stream);
	}
	return count;
}

int standard_resource_file_save(resource_file_t rf, FILE *stream);
int extended_resource_file_save(resource_file_t rf, FILE *stream);

int resource_file_save(resource_file_t rf, enum resource_file_flags flags, const char *restrict path)
{
	assert(rf != NULL);

	// Use the path contained in the resource_file_t reference, unless a path is
	// specified by the caller.
	const char *save_path = (path != NULL) ? path : rf->path;
	if (save_path == NULL) {
		fprintf(stderr, "Unable to save resource file due to no file path being specified.\n");
		return RF_MISSING_PATH;
	}

	// Begin creating a new file. To do this we need to fetch a file handle to the
	// file.
	FILE *stream = fopen(save_path, "wb");
	if (stream == NULL) {
		fprintf(stderr, "Failed to save resource file. File could not be opened/created.\n");
		return RF_FILE;
	}

	// Seek to the beginning of the file, and make sure we are overwriting content.
	fseek(stream, 0L, SEEK_SET);

	// Switch over to the appropriate save routine. This depends on two things, is
	// the resource file set to be an extended resource fork or has the caller requested
	// an extended resource fork. If either is true, then we need to save an extended
	// resource fork, otherwise we save a standard one.
	if (rf->type == resource_fork_extended || (flags & rf_save_extended)) {
		int err = extended_resource_file_save(rf, stream);
		fclose(stream);
		return err;
	}
	else {
		int err = standard_resource_file_save(rf, stream);
		fclose(stream);
		return err;
	}
}

int standard_resource_file_save(resource_file_t rf, FILE *stream)
{
	uint8_t tmp8 = 0;
	uint16_t tmp16 = 0;
	uint32_t tmp32 = 0;

	uint32_t data_offset = 0x100;
	uint32_t data_size = 0;
	uint32_t map_offset = 0;
	uint32_t map_size = 0;

	// The first aspect of the resource file to save is the preamble. However,
	// we don't actually know all of the details yet. The details we do not yet
	// know are:
	//	- map_offset (requires knowledge of data_size)
	//	- data_size  (need to save data first)
	// 	- map_size	 (need to save map first)
	// We can write the data_offset, so we'll do that and then pad out with 0's.
	// The data_offset will be 256 bytes from the beginning.
	if (file_write(&data_offset, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write preamble data_offset.\n");
		return RF_WRITE;
	}

	size_t pad_count = data_offset - sizeof(uint32_t);
	if (file_pad(0x00, pad_count, stream) != pad_count) {
		fprintf(stderr, "Failed to pad preamble to required length.\n");
		return RF_WRITE;
	}

	// At this point we can begin saving the resource data. For this we simply
	// need to step through each of the resources, and record the offset in 
	// which we are beginning to save them.
	struct resource_type *type_ptr = NULL;
	struct resource *resource_ptr = NULL;
	for (int type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (int res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];
			
			uint32_t offset = ftell(stream) - data_offset;

			// First write the resource size to the stream, followed by the 
			// contents of the resource. 
			uint32_t size = (uint32_t)(resource_ptr->data_size & 0xFFFFFFFF);
			if (file_write(&size, sizeof(uint32_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to correctly write resource data size.\n");
				return RF_WRITE;
			}

			if (size > 0 && file_write_flags(resource_ptr->data, size, 1, F_NONE, stream) != 1) {
				fprintf(stderr, "Failed to correctly write resource data.\n");
				return RF_WRITE;
			}

			// Store the data offset in the resource.
			resource_ptr->data_offset = (uint64_t)offset;

#if defined(DEBUG_TEST)
			printf("  - wrote resource '%s' %lld data at %08x\n", 
				type_ptr->code, resource_ptr->id, offset);
#endif
		}
	}

	// At this point we know both the map_offset and the data_size. However it
	// is best to wait for completion of the resource map, before writing the
	// preamble.
	map_offset = ftell(stream);
	data_size = map_offset - data_offset;

	// This leads to setting up the resource map information. We should have 
	// everything we need currently. The only complication is going to be the
	// resource names.
	// The first part of the resource fork is a clone of the preamble, used as
	// a verification. Repeat what was done above, but omit the large padding.
	if (file_write(&data_offset, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_offset.\n");
		return RF_WRITE;
	}

	// Pad out by 3 extra fields worth of zeros to account for the future map_offset,
	// data_size and map_size values.
	pad_count = sizeof(uint32_t) * 3;
	if (file_pad(0x00, pad_count, stream) != pad_count) {
		fprintf(stderr, "Failed to pad resource map preamble to required length.\n");
		return RF_WRITE;
	}

	// The next 6 bytes are used by the MacOS Resource Manager, and thus not 
	// important to us here.
	if (file_pad(0x00, 6, stream) != 6) {
		fprintf(stderr, "Failed to write required bytes.\n");
		return RF_WRITE;
	}

	if (file_write(&rf->rsrc.map.flags, sizeof(uint16_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map flags.\n");
		return RF_WRITE;
	}

	// This save algorithm ensures that this value is _always_ 28. Update the
	// value and then write it.
	rf->rsrc.map.type_list_offset = 28;
	tmp16 = (uint16_t)(rf->rsrc.map.type_list_offset & 0xFFFF);
	if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map type list offset.\n");
		return RF_WRITE;
	}

	// We need to calculate the name list offset, but this is easily done. It is
	// the type_list_offset + (type_count * sizeof(type_record)) + (resource_count * sizeof(resource_record))
	rf->rsrc.map.name_list_offset = ((rf->rsrc.type_count + 1) * STANDARD_RESOURCE_TYPE_LENGTH);
	rf->rsrc.map.name_list_offset += ((rf->rsrc.resource_count + 1) * STANDARD_RESOURCE_LENGTH);
	rf->rsrc.map.name_list_offset += rf->rsrc.map.type_list_offset + sizeof(uint16_t);
	tmp16 = (uint16_t)(rf->rsrc.map.name_list_offset & 0xFFFF);
	if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map name list offset.\n");
		return RF_WRITE;
	}

	// Next we can move on to writing out the actual resource metadata. This simply
	// involves stepping through everything and writing out the appropriate information.
	tmp16 = rf->rsrc.type_count;
	if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource type count.\n");
		return RF_WRITE;
	}

	// Calculate the first resource offset.
	uint16_t resource_offset = 2 + (rf->rsrc.type_count + 1) * STANDARD_RESOURCE_TYPE_LENGTH;
	for (int type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];

		// Convert the type name into a MacRoman string.
		size_t typecode_size = 4;
		const char *macroman_typecode = macroman_from_utf8(type_ptr->code, &typecode_size);
		if (file_write((void *)macroman_typecode, 1, 4, stream) != 4) {
			fprintf(stderr, "Failed to write resource type code.\n");
			return RF_WRITE;
		}
		free((void *)macroman_typecode);

		// The number of resources - 1 associated with this type.
		tmp16 = (uint16_t)(type_ptr->resource_count & 0xFFFF);
		if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
			fprintf(stderr, "Failed to write resource count.\n");
			return RF_WRITE;
		}

		// The offset of the first resource from the start of the type list.
		// After writing it, calculate the start of the first resource for the 
		// next type.
		if (file_write(&resource_offset, sizeof(uint16_t), 1, stream) != 1) {
			fprintf(stderr, "Failed to write first resource offset.\n");
			return RF_WRITE;
		}
		resource_offset += (tmp16 + 1) * STANDARD_RESOURCE_LENGTH;
	}

	uint16_t name_list_offset = 0;
	for (int type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (int res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];

			// The first field to write is the Resource ID.
			tmp16 = (int16_t)(resource_ptr->id & 0x7FFF) * (resource_ptr->id < 0 ? -1 : 1);
			if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource id.\n");
				return RF_WRITE;
			}

			// The offset of the resource name in the name list.
			// Determine the offset for the next name. To do this add the length
			// of the name to the offset (up to 255 bytes), plus and additional 
			// 1 byte for the length of the name. If the name is NULL then write
			// the offset as 0xFFFF, to indicate no name.
			if (resource_ptr->name) {
				if (file_write(&name_list_offset, sizeof(uint16_t), 1, stream) != 1) {
					fprintf(stderr, "Failed to write resource name offset.\n");
					return RF_WRITE;
				}
				size_t len = 0;
				free((void *)macroman_from_utf8(resource_ptr->name, &len));
				name_list_offset += (len >= 0x100 ? 0xFF : len) + 1;
			}
			else {
				tmp16 = 0xFFFF;
				if (file_write(&tmp16, sizeof(uint16_t), 1, stream) != 1) {
					fprintf(stderr, "Failed to write resource name offset.\n");
					return RF_WRITE;
				}
			}

			// The resource flags
			if (file_write(&resource_ptr->flags, sizeof(uint8_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource attributes.\n");
				return RF_WRITE;
			}

			// The data offset is 3 bytes, which means we need to split the offset
			// up into 3 bytes, and discard the hi-byte.
			uint8_t offset[3] = {
				(resource_ptr->data_offset & 0xFF0000) >> 16,
				(resource_ptr->data_offset & 0xFF00) >> 8,
				(resource_ptr->data_offset & 0xFF),
			};
			if (file_write(offset, sizeof(uint8_t), 3, stream) != 3) {
				fprintf(stderr, "Failed to write resource data offset.\n");
				return RF_WRITE;
			}

			// The final field is the handle. This is an internal value from the
			// ResourceManager in Classic MacOS, so just leave this as 0.
			tmp32 = 0;
			if (file_write(&tmp32, sizeof(uint32_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource handle.\n");
				return RF_WRITE;
			}
		}
	}

	// We now need to write out each of the names of the resources out to the 
	// file.
	for (int type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (int res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];

			// We only need to write a name if there is a name for the resource.
			if (resource_ptr->name == NULL) {
				continue;
			}

			// If the name is longer than 255 bytes, then just truncate the 
			// excess.
			size_t len = 0;
			const char *name = macroman_from_utf8(resource_ptr->name, &len);
			len = len >= 0x100 ? 0xFF : len;

			tmp8 = (uint8_t)(len & 0xFF);
			if (file_write(&tmp8, sizeof(uint8_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource name length.\n");
				return RF_WRITE;
			}

			if (file_write_flags((void *)name, sizeof(uint8_t), len, F_NONE, stream) != len) {
				fprintf(stderr, "Failed to write resource name content.\n");
				return RF_WRITE;
			}

			free((void *)name);
		}
	}

	// Finally we need to write out the preamble values that we calculated earlier,
	// and finish the calculation for the resource map. First write out the main
	// preamble...
	map_size = ftell(stream) - map_offset;

	fseek(stream, sizeof(uint32_t), SEEK_SET);
	if (file_write(&map_offset, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&data_size, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_size.\n");
		return RF_WRITE;
	}

	if (file_write(&map_size, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_size.\n");
		return RF_WRITE;
	}

	// ... and then the check preamble.
	fseek(stream, map_offset, SEEK_SET);
	if (file_write(&data_offset, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&map_offset, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&data_size, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_size.\n");
		return RF_WRITE;
	}

	if (file_write(&map_size, sizeof(uint32_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_size.\n");
		return RF_WRITE;
	}

	// Everything successfully written!
	return RF_OK;
}

int extended_resource_file_save(resource_file_t rf, FILE *stream)
{
	uint8_t tmp8 = 0;
	uint32_t tmp32 = 0;
	uint64_t tmp64 = 0;

	uint64_t data_offset = 0x100;
	uint64_t data_size = 0;
	uint64_t map_offset = 0;
	uint64_t map_size = 0;

	// This is an extended ResourceFork, so we need to write the format version
	// field first.
	tmp64 = 1;
	if (file_write(&tmp64, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write preamble format version.\n");
		return RF_WRITE;
	}

	// The first aspect of the resource file to save is the preamble. However,
	// we don't actually know all of the details yet. The details we do not yet
	// know are:
	//	- map_offset (requires knowledge of data_size)
	//	- data_size  (need to save data first)
	// 	- map_size	 (need to save map first)
	// We can write the data_offset, so we'll do that and then pad out with 0's.
	// The data_offset will be 256 bytes from the beginning.
	if (file_write(&data_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write preamble data_offset.\n");
		return RF_WRITE;
	}

	size_t pad_count = data_offset - (sizeof(uint64_t) * 2);
	if (file_pad(0x00, pad_count, stream) != pad_count) {
		fprintf(stderr, "Failed to pad preamble to required length.\n");
		return RF_WRITE;
	}

	// At this point we can begin saving the resource data. For this we simply
	// need to step through each of the resources, and record the offset in 
	// which we are beginning to save them.
	struct resource_type *type_ptr = NULL;
	struct resource *resource_ptr = NULL;
	for (uint64_t type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (uint64_t res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];
			
			uint64_t offset = ftell(stream) - data_offset;

			// First write the resource size to the stream, followed by the 
			// contents of the resource. 
			if (file_write(&resource_ptr->data_size, sizeof(uint64_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to correctly write resource data size.\n");
				return RF_WRITE;
			}

			if (file_write_flags(resource_ptr->data, resource_ptr->data_size, 1, F_NONE, stream) != 1) {
				fprintf(stderr, "Failed to correctly write resource data.\n");
				return RF_WRITE;
			}

			// Store the data offset in the resource.
			resource_ptr->data_offset = offset;

#if defined(DEBUG_TEST)
			printf("  - wrote resource '%s' %lld data at %016llx\n", 
				type_ptr->code, resource_ptr->id, offset);
#endif
		}
	}

	// At this point we know both the map_offset and the data_size. However it
	// is best to wait for completion of the resource map, before writing the
	// preamble.
	map_offset = ftell(stream);
	data_size = map_offset - data_offset;

	// This leads to setting up the resource map information. We should have 
	// everything we need currently. The only complication is going to be the
	// resource names.
	// The first part of the resource fork is a clone of the preamble, used as
	// a verification. Repeat what was done above, but omit the large padding.
	if (file_write(&data_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_offset.\n");
		return RF_WRITE;
	}

	// Pad out by 3 extra fields worth of zeros to account for the future map_offset,
	// data_size and map_size values.
	pad_count = sizeof(uint64_t) * 3;
	if (file_pad(0x00, pad_count, stream) != pad_count) {
		fprintf(stderr, "Failed to pad resource map preamble to required length.\n");
		return RF_WRITE;
	}

	// The next 6 bytes are used by the MacOS Resource Manager, and thus not 
	// important to us here.
	if (file_pad(0x00, 6, stream) != 6) {
		fprintf(stderr, "Failed to write required bytes.\n");
		return RF_WRITE;
	}

	if (file_write(&rf->rsrc.map.flags, sizeof(uint16_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map flags.\n");
		return RF_WRITE;
	}

	// This save algorithm ensures that this value is _always_ 56. Update the
	// value and then write it.
	rf->rsrc.map.type_list_offset = 56;
	if (file_write(&rf->rsrc.map.type_list_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map type list offset.\n");
		return RF_WRITE;
	}

	// We need to calculate the name list offset, but this is easily done. It is
	// the type_list_offset + (type_count * sizeof(type_record)) + (resource_count * sizeof(resource_record))
	rf->rsrc.map.name_list_offset = ((rf->rsrc.type_count + 1) * EXTENDED_RESOURCE_TYPE_LENGTH);
	rf->rsrc.map.name_list_offset += ((rf->rsrc.resource_count + 1) * EXTENDED_RESOURCE_LENGTH);
	rf->rsrc.map.name_list_offset += rf->rsrc.map.type_list_offset + sizeof(uint64_t);
	if (file_write(&rf->rsrc.map.name_list_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map name list offset.\n");
		return RF_WRITE;
	}

	// Next we can move on to writing out the actual resource metadata. This simply
	// involves stepping through everything and writing out the appropriate information.
	if (file_write(&rf->rsrc.type_count, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource type count.\n");
		return RF_WRITE;
	}

	// Calculate the first resource offset.
	uint64_t resource_offset = sizeof(uint64_t) + (rf->rsrc.type_count + 1) * EXTENDED_RESOURCE_TYPE_LENGTH;
	for (uint64_t type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];

		// Convert the type name into a MacRoman string.
		size_t typecode_size = 4;
		const char *macroman_typecode = macroman_from_utf8(type_ptr->code, &typecode_size);
		if (file_write((void *)macroman_typecode, 1, 4, stream) != 4) {
			fprintf(stderr, "Failed to write resource type code.\n");
			return RF_WRITE;
		}
		free((void *)macroman_typecode);

		// The number of resources - 1 associated with this type.
		if (file_write(&type_ptr->resource_count, sizeof(uint64_t), 1, stream) != 1) {
			fprintf(stderr, "Failed to write resource count.\n");
			return RF_WRITE;
		}

		// The offset of the first resource from the start of the type list.
		// After writing it, calculate the start of the first resource for the 
		// next type.
		if (file_write(&resource_offset, sizeof(uint64_t), 1, stream) != 1) {
			fprintf(stderr, "Failed to write first resource offset.\n");
			return RF_WRITE;
		}
		resource_offset += (type_ptr->resource_count + 1) * EXTENDED_RESOURCE_LENGTH;
	}

	uint64_t name_list_offset = 0;
	for (uint64_t type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (uint64_t res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];

			// The first field to write is the Resource ID.
			if (file_write(&resource_ptr->id, sizeof(uint64_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource id.\n");
				return RF_WRITE;
			}

			// The offset of the resource name in the name list.
			// Determine the offset for the next name. To do this add the length
			// of the name to the offset (up to 255 bytes), plus and additional 
			// 1 byte for the length of the name. If the name is NULL then write
			// the offset as 0xFFFF, to indicate no name.
			if (resource_ptr->name) {
				if (file_write(&name_list_offset, sizeof(uint64_t), 1, stream) != 1) {
					fprintf(stderr, "Failed to write resource name offset.\n");
					return RF_WRITE;
				}
				size_t len = 0;
				free((void *)macroman_from_utf8(resource_ptr->name, &len));
				name_list_offset += (len >= 0x100 ? 0xFF : len) + 1;
			}
			else {
				tmp64 = 0xFFFFFFFFFFFFFFFF;
				if (file_write(&tmp64, sizeof(uint64_t), 1, stream) != 1) {
					fprintf(stderr, "Failed to write resource name offset.\n");
					return RF_WRITE;
				}
			}

			// The resource flags
			if (file_write(&resource_ptr->flags, sizeof(uint8_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource attributes.\n");
				return RF_WRITE;
			}

			// Write the data offset for the resource.
			if (file_write(&resource_ptr->data_offset, sizeof(uint64_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource data offset.\n");
				return RF_WRITE;
			}

			// The final field is the handle. This is an internal value from the
			// ResourceManager in Classic MacOS, so just leave this as 0.
			tmp32 = 0;
			if (file_write(&tmp32, sizeof(uint32_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource handle.\n");
				return RF_WRITE;
			}
		}
	}

	// We now need to write out each of the names of the resources out to the 
	// file.
	for (uint64_t type_idx = 0; type_idx <= rf->rsrc.type_count; ++type_idx) {
		type_ptr = &rf->rsrc.types[type_idx];
		for (uint64_t res_idx = 0; res_idx <= type_ptr->resource_count; ++res_idx) {
			resource_ptr = &rf->rsrc.resources[type_ptr->resource_index + res_idx];

			// We only need to write a name if there is a name for the resource.
			if (resource_ptr->name == NULL) {
				continue;
			}

			// If the name is longer than 255 bytes, then just truncate the 
			// excess.
			size_t len = 0;
			const char *name = macroman_from_utf8(resource_ptr->name, &len);
			len = len >= 0x100 ? 0xFF : len;

			tmp8 = (uint8_t)(len & 0xFF);
			if (file_write(&tmp8, sizeof(uint8_t), 1, stream) != 1) {
				fprintf(stderr, "Failed to write resource name length.\n");
				return RF_WRITE;
			}

			if (file_write_flags((void *)name, sizeof(uint8_t), len, F_NONE, stream) != len) {
				fprintf(stderr, "Failed to write resource name content.\n");
				return RF_WRITE;
			}

			free((void *)name);
		}
	}

	// Finally we need to write out the preamble values that we calculated earlier,
	// and finish the calculation for the resource map. First write out the main
	// preamble...
	map_size = ftell(stream) - map_offset;

	fseek(stream, sizeof(uint64_t) * 2, SEEK_SET);
	if (file_write(&map_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&data_size, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_size.\n");
		return RF_WRITE;
	}

	if (file_write(&map_size, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_size.\n");
		return RF_WRITE;
	}

	// ... and then the check preamble.
	fseek(stream, map_offset, SEEK_SET);
	if (file_write(&data_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&map_offset, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_offset.\n");
		return RF_WRITE;
	}

	if (file_write(&data_size, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble data_size.\n");
		return RF_WRITE;
	}

	if (file_write(&map_size, sizeof(uint64_t), 1, stream) != 1) {
		fprintf(stderr, "Failed to write resource map preamble map_size.\n");
		return RF_WRITE;
	}

	// Everything successfully written!
	return RF_OK;
}
