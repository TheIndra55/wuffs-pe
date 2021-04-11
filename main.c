#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#define WUFFS_IMPLEMENTATION
#define WUFFS_CONFIG__STATIC_FUNCTIONS
#define WUFFS_CONFIG__MODULE__BASE

#include "parse.c"

//#include "../../release/c/wuffs-unsupported-snapshot.c"

#define SRC_BUFFER_SIZE (128 * 1024)
static uint8_t src_buffer[SRC_BUFFER_SIZE];

// this is very fast PoC code to test the wuffs code, it contains many red flags
// there are no checks on the buffer if the file is too big and more, it should be refactored before use
int main(int argc, char **argv)
{
    wuffs_pe__parser h;
    wuffs_base__status status = wuffs_pe__parser__initialize(&h, sizeof h, WUFFS_VERSION, 0);
    if (!wuffs_base__status__is_ok(&status))
    {
        fprintf(stderr, "%s\n", wuffs_base__status__message(&status));
        return 1;
    }

    wuffs_base__io_buffer src;
    src.data.ptr = src_buffer;
    src.data.len = SRC_BUFFER_SIZE;
    src.meta.wi = SRC_BUFFER_SIZE;
    src.meta.ri = 0;
    src.meta.pos = 0;
    src.meta.closed = false;

    FILE* f;
#ifdef WIN32
    fopen_s(f, argv[1], "rb");
    fread_s(src_buffer, SRC_BUFFER_SIZE, 1, SRC_BUFFER_SIZE, f);
#else
    FILE* f = fopen(argv[1], "rb");
    fread(src_buffer, 1, SRC_BUFFER_SIZE, f);
#endif

    status = wuffs_pe__parser__parse(&h, &src);
    if (!wuffs_base__status__is_ok(&status))
    {
        fprintf(stderr, "%s\n", wuffs_base__status__message(&status));
        return 1;
    }

    // seek to PE header
    src.meta.ri = h.private_impl.f_file_header_pos;

    status = wuffs_pe__parser__read_image_file_header(&h, &src);
    if (!wuffs_base__status__is_ok(&status))
    {
        fprintf(stderr, "%s\n", wuffs_base__status__message(&status));
        return 1;
    }

    // list all date directories; exports, imports etc
    for(int i = 0; i < 16; i++)
    {
        wuffs_pe__image_data_directory dir = h.private_impl.f_image_data_directories[i];
        printf("%d: %04x %04x\n", i, dir.private_impl.f_size, dir.private_impl.f_virtual_address);
    }

    // list all sections
    for(int i = 0; i < h.private_impl.f_number_of_sections; i++)
    {
        wuffs_pe__image_section_header dir = h.private_impl.f_image_sections[i];
        printf("%s %04x %04x\n", dir.private_impl.f_name, dir.private_impl.f_virtual_size, dir.private_impl.f_virtual_address);
    }

    return 0;
}
