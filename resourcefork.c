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
#include "libEncoding/macroman.h"
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

// MARK: - Debug/Test App

char rf_error[1024] = {0};

#if defined(DEBUG_TEST)
int main(int argc, const char **argv)
{
	resource_file_t rf = NULL;
	if (resource_file_open(&rf, argv[1]) != RF_OK) {
		printf("%s\n", rf_error);
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
};

struct resource {
	int16_t id;
	const char *name;
	uint8_t flags;
	uint32_t data_offset;
};

struct resource_fork {
	struct resource_fork_preamble preamble;
	struct resource_fork_map map;
	uint16_t type_count;
	uint32_t resource_count;
	struct resource_type *types;
	struct resource *resources;
};

struct resource_file {
	const char *path;
	FILE *handle;
	struct resource_fork rsrc;
};

// MARK: - File Extensions (Reading Big Endian Values)

size_t fread_big(
	void *restrict ptr, 
	size_t size, 
	size_t nitems, 
	FILE *restrict stream
) {
	if (!stream) {
		return 0;
	}
	
	size_t count = 0;
	while (!feof(stream) && nitems--) {
		// Get a representation that we can work with easily.
		uint8_t *p = (uint8_t *)ptr;	
		fread(p, size, 1, stream);

		// Perform the big endian swap. However this is only done
		// on integer values (2, 3 & 4 bytes).
		if (size >= 2 && size <= 4) {
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
	(*rf)->handle = handle;
	(*rf)->path = calloc(strlen(path) + 1, 1);

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
		fclose(rf->handle);
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
	fseek(rf->handle, 0L, SEEK_SET);

	// Read out 4 'DLNG' values, directly into the preamble.
	fread_big(preamble, sizeof(uint32_t), 4, rf->handle);

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
	fseek(rf->handle, rf->rsrc.preamble.map_offset, SEEK_SET);
	if (fread_big(&chk_preamble, sizeof(uint32_t), 4, rf->handle) != 4) {
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
	fseek(rf->handle, 6L, SEEK_CUR);
	
	if (fread_big(&rf->rsrc.map.flags, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork flags.");
		return RF_PARSE;
	}

	if (fread_big(&rf->rsrc.map.type_list_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
		snprintf(rf_error, sizeof(rf_error), "Failed to read resource fork type list offset.");
		return RF_PARSE;
	}

	if (fread_big(&rf->rsrc.map.name_list_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
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
	fseek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.type_list_offset, SEEK_SET);
	printf("@ -> %ld\n", ftell(rf->handle));

	// The first value that we need to read tells us how many resource types exist within
	// the resource fork. This will tell us how large the `types` array needs to be, and
	// how many types we need to parse.
	if (fread_big(&rf->rsrc.type_count, sizeof(uint16_t), 1, rf->handle) != 1) {
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
		if ((n = fread(raw_code, 1, 4, rf->handle)) != 4) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource type code (%d).", n);
			return RF_PARSE;
		}
		rf->rsrc.types[i].code = utf8_from_macroman(raw_code, 4);

		// The next two values are endian specific.
		if (fread_big(&rf->rsrc.types[i].resource_count, sizeof(uint16_t), 1, rf->handle) != 1) {
			snprintf(rf_error, sizeof(rf_error), "Failed to read resource count for type.");
			return RF_PARSE;
		}

		if (fread_big(&rf->rsrc.types[i].resource_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
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
	for (int i = 0; i <= rf->rsrc.type_count; ++i) {
		int offset = rf->rsrc.types[i].resource_offset;
		fseek(rf->handle, 
			  rf->rsrc.preamble.map_offset + rf->rsrc.map.type_list_offset + offset, 
			  SEEK_SET);

		// Read each of the resources. This involves parsing out the appropriate data
		// and inserting it into each of the allocated resource records.
		for (int j = offset, k = 0; k <= rf->rsrc.types[i].resource_count; ++k, ++j) {
			if (fread_big(&rf->rsrc.resources[j].id, sizeof(int16_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource id.");
				return RF_PARSE;
			}
			
			uint16_t name_offset = 0;
			if (fread_big(&name_offset, sizeof(uint16_t), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource name offset.");
				return RF_PARSE;
			}

			if (fread(&rf->rsrc.resources[j].flags, 1, 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource flags.");
				return RF_PARSE;
			}

			uint8_t offset_raw[3] = { 0 };
			if (fread_big(offset_raw, sizeof(offset_raw), 1, rf->handle) != 1) {
				snprintf(rf_error, sizeof(rf_error), "Failed to read resource data offset.");
				return RF_PARSE;
			}
			rf->rsrc.resources[j].data_offset = (offset_raw[0] << 16) | (offset_raw[1] << 8) | (offset_raw[0]);
			
			// Now that all of the resource fields have been extracted, find and parse the name
			// of the resource. However if the name offset is 0xFFFF, then we know there is no
			// name assigned.
			if (name_offset != UINT16_MAX) {
				long cur_pos = ftell(rf->handle);
				fseek(rf->handle, rf->rsrc.preamble.map_offset + rf->rsrc.map.name_list_offset + name_offset, SEEK_SET);
			
				uint8_t name_length = 0;
				if (fread(&name_length, 1, 1, rf->handle) != 1) {
					snprintf(rf_error, sizeof(rf_error), "Failed to determine the length of the resource name.");
					return RF_PARSE;
				}

				char raw_name[256] = { 0 };
				if (fread(&raw_name, 1, name_length, rf->handle) != name_length) {
					snprintf(rf_error, sizeof(rf_error), "Failed to read the resource name.");
					return RF_PARSE;
				}

				rf->rsrc.resources[j].name = utf8_from_macroman(raw_name, name_length);
				fseek(rf->handle, cur_pos, SEEK_SET);
			}

#if defined(DEBUG_TEST)
			printf("  '%s' %d: %s (%#06x)\n", 
					rf->rsrc.types[i].code, rf->rsrc.resources[j].id, 
					rf->rsrc.resources[j].name, rf->rsrc.resources[j].data_offset);
#endif

			// Skip over the next 4 bytes.
			fseek(rf->handle, 4L, SEEK_CUR);
		}
	}	

	return RF_OK;
}

int resource_file_parse(resource_file_t rf)
{
	int err = 0;

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

