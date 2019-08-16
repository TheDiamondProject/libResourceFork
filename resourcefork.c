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
	if (resource_file_open(&rf, argv[1]) != RF_OK) {
		printf("%s\n", rf_error);
	} else {
		resource_file_close(rf);
	}
	return 0;
}
#endif

// MARK: - ResourceFork Data Structures

struct resource_fork_preamble {
	uint32_t data_offset;
	uint32_t map_offset;
	uint32_t data_size;
	uint32_t map_size;
} __attribute__((packed));

struct resource_fork_map {
	uint16_t flags;
	uint16_t type_list_offset;
	uint16_t name_list_offset;
};

struct resource_type {
	const char *code;
	uint16_t resource_count;
	uint16_t resource_offset;
	uint32_t resource_index;
};

struct resource {
	int16_t id;
	const char *name;
	uint8_t flags;
	uint32_t data_offset;
	uint32_t data_size;
	void *data;
};

struct resource_fork {
	struct resource_fork_preamble preamble;
	struct resource_fork_map map;
	uint16_t type_count;
	uint32_t resource_count;
	struct resource_type *types;
	struct resource *resources;
};

struct data_buffer {
	uint8_t *data;
	ssize_t size;
	off_t pos;
};

struct resource_file {
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
		// on integer values (2, 3 & 4 bytes).
		if ((flags & F_ENDIAN) && (size >= 2 && size <= 4)) {
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

int resource_file_open(resource_file_t *rf, const char *restrict path)
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

	// File is open and known good. Start setting up the structure
	// and allocations.
	*rf = calloc(1, sizeof(**rf));
	(*rf)->path = calloc(strlen(path) + 1, 1);

	// Load the contents of the file in to the buffer.
	struct data_buffer *buffer = calloc(1, sizeof(*buffer));
	fseek(handle, 0L, SEEK_END);
	buffer->size = ftell(handle);
	buffer->data = calloc(1, buffer->size);
	buffer->pos = 0;
	fseek(handle, 0L, SEEK_SET);

#if defined(DEBUG_TEST)
	printf("loading resource fork into buffer (%p): %d bytes...\n", buffer, buffer->size);
#endif

	if (fread(buffer->data, 1, buffer->size, handle) != buffer->size) {
#if defined(DEBUG_TEST)
		printf("failed to load resource fork\n");
#endif
		fclose(handle);
		resource_file_free(*rf);
		return RF_FILE;
	}

#if defined(DEBUG_TEST)
	printf("finishing resource fork load\n");
#endif

	fclose(handle);
	(*rf)->handle = buffer;

	// Copy the file path string into it's new home. We will/may need
	// it later.
	strncpy((void *)(*rf)->path, path, strlen(path));

	// A major part of opening the file is parsing the resource map.
	// If the resource map is invalid, then we can infer that the
	// file is not a resource file and thus should be ignored.
	if ((err = resource_file_parse(*rf)) != RF_OK) {
		goto RSRC_PARSE_ERROR;
	}

	// Successfully completed opening the resource fork.
	return RF_OK;

RSRC_PARSE_ERROR:
	// Clean up and make sure we're not leaking memory!
	resource_file_free(*rf);
	return RF_PARSE;
}

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

	// Read out 4 'DLNG' values, directly into the preamble.
	buffer_read(preamble, sizeof(uint32_t), 4, rf->handle);

#if defined(DEBUG_TEST)
	printf("data_offset: %08x\n", preamble->data_offset);
	printf("map_offset: %08x\n", preamble->map_offset);
	printf("data_size: %d\n", preamble->data_size);
	printf("map_size: %d\n", preamble->map_size);
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
	int err = 0;

	// Jump to the start of the resource map. The start of the map has a copy of the preamble,
	// which we can use as a "validation/checksum" for the resource file "integrity".
	struct resource_fork_preamble chk_preamble = { 0 };
	buffer_seek(rf->handle, rf->rsrc.preamble.map_offset, SEEK_SET);
	if (buffer_read(&chk_preamble, sizeof(uint32_t), 4, rf->handle) != 4) {
		snprintf(rf_error, sizeof(rf_error),
			"Error validating and checking resource fork preamble.");
		return RF_PARSE;
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

	if (buffer_read(&rf->rsrc.map.type_list_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork type list offset.");
		return RF_PARSE;
	}

	if (buffer_read(&rf->rsrc.map.name_list_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork name list offset.");
		return RF_PARSE;
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
	int err = 0;

	// The first job is to seek to the appropriate location in the file.
	buffer_seek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.type_list_offset, SEEK_SET);
	printf("@ -> %ld\n", buffer_tell(rf->handle));

	// The first value that we need to read tells us how many resource types exist within
	// the resource fork. This will tell us how large the `types` array needs to be, and
	// how many types we need to parse.
	if (buffer_read(&rf->rsrc.type_count, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to determine number of resource types.");
		return RF_PARSE;
	}

	// Allocate the memory needed to store the type information.
	rf->rsrc.types = calloc(rf->rsrc.type_count + 1, sizeof(*rf->rsrc.types));
	
	// Now parse out each of the resource types
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		// The resource type code is the first thing to be read. This is 4 bytes long, and is
		// _not_ endian specific.
		int n = 0;
		char raw_code[4] = { 0 };
		if ((n = buffer_read_flags(raw_code, 1, 4, F_NONE, rf->handle)) != 4) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource type code (%d).", n);
			return RF_PARSE;
		}
		rf->rsrc.types[i].code = utf8_from_macroman(raw_code, 4);

		// The next two values are endian specific.
		if (buffer_read(&rf->rsrc.types[i].resource_count, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource count for type.");
			return RF_PARSE;
		}

		if (buffer_read(&rf->rsrc.types[i].resource_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource offset for type.");
			return RF_PARSE;
		}

#if defined(DEBUG_TEST)
		// Display some information about the resource type.
		printf("%6d '%s' %d resource(s), offset: %#02x\n",
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
	int err = 0;
	
	// Before anything else is even attempted, we need to know how many resources
	// there are in the resource fork in total. To do this we can add up all of the resource
	// counts in each of the types.
	rf->rsrc.resource_count = 0;
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		rf->rsrc.resource_count += rf->rsrc.types[i].resource_count + 1;
	}

#if defined(DEBUG_TEST)
	printf("there are %d resources in the resource fork.\n", rf->rsrc.resource_count);
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
		for (int j = index_offset, k = 0; k <= rf->rsrc.types[i].resource_count; ++k, ++j, ++index_offset) {
			if (buffer_read(&rf->rsrc.resources[j].id, sizeof(int16_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource id.");
				return RF_PARSE;
			}
			
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

				if (buffer_read(&rf->rsrc.resources[j].data_size, sizeof(uint32_t), 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read resource data size.");
					return RF_PARSE;
				}

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
			printf("  '%s' %d: %s (%#06x) [%d/%d] {%d bytes}\n", 
					rf->rsrc.types[i].code, rf->rsrc.resources[j].id, 
					rf->rsrc.resources[j].name, rf->rsrc.resources[j].data_offset,
					j, rf->rsrc.resource_count, rf->rsrc.resources[j].data_size);
#endif

			// Skip over the next 4 bytes.
			buffer_seek(rf->handle, 4L, SEEK_CUR);
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
	int16_t *id, 
	const char **name,
	uint8_t *data,
	uint32_t *size
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
	int16_t id, 
	const char **name,
	uint8_t *data,
	uint32_t *size
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

	return RF_OK;
}
