


// Code block size in bytes.
static constexpr int code_block_size = 160;

// Code block size in .text section of the binary (the code block itself may
// be shorter). Should be a multiple of 128 >= code_block_size.
// See also CODE_BLOCK_SIZE_TEXT in controller.S.
static constexpr int code_block_size_text = 256;