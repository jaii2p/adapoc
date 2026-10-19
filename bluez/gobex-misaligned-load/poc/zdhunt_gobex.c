/* zdhunt_gobex.c — BlueZ 5.85 gobex header parser micro-fuzz harness.
 *
 * Chain: raw OBEX bytes -> g_obex_header_decode() [gobex-header.c TLV parse]
 *          -> utf16_to_utf8() [:65 alloca((hdr_len-5)/2 + 1) + 2-byte strided read]
 *          -> g_obex_header_get_unicode() [:327]
 *        -> g_obex_packet_decode() (multi-header aggregate loop)
 * Focus: UNICODE header path where attacker hdr_len (16-bit) drives alloca(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "gobex/gobex-header.h"
#include "gobex/gobex-packet.h"

int main(void) {
    unsigned char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) return 0;

    GError *err = NULL;
    gsize parsed = 0;
    GObexHeader *h = g_obex_header_decode(buf, n, G_OBEX_DATA_COPY,
                                          &parsed, &err);
    if (h) {
        const char *s = NULL;
        (void)g_obex_header_get_unicode(h, &s);
        g_obex_header_free(h);
    }
    if (err) g_error_free(err);

    /* full-packet path so the multi-header aggregate loop is also reached */
    err = NULL; parsed = 0;
    GObexPacket *p = g_obex_packet_decode(buf, n, 3, G_OBEX_DATA_COPY, &err);
    if (p) g_obex_packet_free(p);
    if (err) g_error_free(err);
    return 0;
}
