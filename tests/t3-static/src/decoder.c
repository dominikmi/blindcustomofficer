#include <stdio.h>
#include <stdlib.h>
#include <brotli/decode.h>

/* Minimal Brotli decompressor: stdin -> stdout.
   Linked statically against libbrotli*.a — the library exists only as
   machine code inside this ELF. */
int main(void) {
    size_t in_cap = 1 << 20, in_len = 0;
    uint8_t *in = malloc(in_cap);
    if (!in) return 1;
    size_t n;
    while ((n = fread(in + in_len, 1, in_cap - in_len, stdin)) > 0) {
        in_len += n;
        if (in_len == in_cap) {
            in_cap *= 2;
            in = realloc(in, in_cap);
            if (!in) return 1;
        }
    }
    size_t out_cap = in_cap * 4 + 1024, out_len = out_cap;
    uint8_t *out = malloc(out_cap);
    if (!out) return 1;
    BrotliDecoderResult r = BrotliDecoderDecompress(in_len, in, &out_len, out);
    if (r != BROTLI_DECODER_RESULT_SUCCESS) {
        fprintf(stderr, "decompress failed\n");
        return 2;
    }
    fwrite(out, 1, out_len, stdout);
    return 0;
}
