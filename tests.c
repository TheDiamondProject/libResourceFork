#include <libUnit/unit.h>
#include "resourcefork.h"

#if defined(UNIT_TEST)

// MARK: - ResourceFork Definitions

enum resource_fork_type
{
	resource_fork_standard,
	resource_fork_extended,
};

struct resource_file {
	enum resource_fork_type type;
	const char *path;
	struct data_buffer *handle;
	// struct resource_fork rsrc;
};

// MARK: - Preamble Fragment Parser

struct resource_fork_preamble 
{
	uint64_t data_offset;
	uint64_t map_offset;
	uint64_t data_size;
	uint64_t map_size;
} __attribute__((packed));

extern int resource_file_parse_preamble(
	resource_file_t rf,
	struct resource_fork_preamble *preamble
);

TEST_CASE(ResourceForkFragments, ParseStandardResourceForkPreamble)
{
	resource_file_t rf = NULL;

	// Load the ResourceFork and ensure it exists.
	int err = resource_file_open(&rf, rf_no_parse, "ResourceFiles/Fragments/StandardPreamble");
	ASSERT_EQ(err, RF_OK);

	// Call the preamble parsing function, and ensure the result is what is 
	// expected.
	struct resource_fork_preamble preamble = { 0 };
	err = resource_file_parse_preamble(rf, &preamble);
	ASSERT_EQ(err, RF_OK);

	ASSERT_EQ(rf->type, resource_fork_standard);

	ASSERT_EQ(preamble.data_offset, 0xDEADBEEF);
	ASSERT_EQ(preamble.map_offset, 0xCAFEBABE);
	ASSERT_EQ(preamble.data_size, 0xFEEDF00D);
	ASSERT_EQ(preamble.map_size, 0xBEADFACE);
}

TEST_CASE(ResourceForkFragments, ParseExtendedResourceForkPreamble)
{
	resource_file_t rf = NULL;

	// Load the ResourceFork and ensure it exists.
	int err = resource_file_open(&rf, rf_no_parse, "ResourceFiles/Fragments/ExtendedPreamble");
	ASSERT_EQ(err, RF_OK);

	// Call the preamble parsing function, and ensure the result is what is 
	// expected.
	struct resource_fork_preamble preamble = { 0 };
	err = resource_file_parse_preamble(rf, &preamble);
	ASSERT_EQ(err, RF_OK);

	ASSERT_EQ(rf->type, resource_fork_extended);

	ASSERT_EQ(preamble.data_offset, 0x2222222222222222);
	ASSERT_EQ(preamble.map_offset, 0x3333333333333333);
	ASSERT_EQ(preamble.data_size, 0x4444444444444444);
	ASSERT_EQ(preamble.map_size, 0x5555555555555555);
}

// MARK: - Main Test Launcher

int main(int argc, const char **argv)
{
	return start_tests();
}

#endif
