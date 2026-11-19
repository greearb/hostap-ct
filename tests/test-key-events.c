/*
 * Regression tests for key events delivered to control interface monitors.
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <assert.h>
#include "common.h"
#include "wpa_debug.h"

static char last_event[512];
static unsigned int events;
static int context;


static void event_cb(void *ctx, int level, enum wpa_msg_type type,
		     const char *txt, size_t len)
{
	assert(ctx == &context);
	assert(level == MSG_INFO);
	assert(type == WPA_MSG_PER_INTERFACE);
	assert(len < sizeof(last_event));
	os_memcpy(last_event, txt, len);
	last_event[len] = '\0';
	events++;
}


static void expect_event(const char *title, const char *event, size_t len)
{
	static const char hex[] =
		"000102030405060708090a0b0c0d0e0f"
		"101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f"
		"303132333435363738393a3b3c3d3e3f"
		"404142434445464748494a4b4c4d4e4f"
		"505152535455565758595a5b5c5d5e5f"
		"606162636465666768696a6b6c6d6e6f"
		"707172737475767778797a7b7c7d7e7f";
	char expected[sizeof(last_event)];
	u8 key[128];
	size_t i, prefix;
	unsigned int before = events;

	assert(len <= sizeof(key));
	for (i = 0; i < sizeof(key); i++)
		key[i] = i;
	prefix = os_snprintf(expected, sizeof(expected), "%s ", event);
	os_memcpy(expected + prefix, hex, 2 * len);
	expected[prefix + 2 * len] = '\0';
	wpa_hexdump_key(&context, MSG_DEBUG, title, key, len);
	assert(events == before + 1);
	assert(os_strcmp(last_event, expected) == 0);
}


static void expect_debug_dump(int show_keys, int debug_level,
			      const char *expected)
{
	static const char key_hex[] =
		"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f";
	FILE *capture;
	char output[512];
	size_t len;
	int saved_stdout;

	assert(fflush(stdout) == 0);
	capture = tmpfile();
	assert(capture);
	saved_stdout = dup(STDOUT_FILENO);
	assert(saved_stdout >= 0);
	assert(dup2(fileno(capture), STDOUT_FILENO) >= 0);
	wpa_debug_show_keys = show_keys;
	wpa_debug_level = debug_level;
	expect_event("WPA: GTK", "WPA: GTK", 16);
	assert(fflush(stdout) == 0);
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	rewind(capture);
	len = fread(output, 1, sizeof(output) - 1, capture);
	assert(!ferror(capture));
	output[len] = '\0';
	fclose(capture);
	if (expected)
		assert(os_strstr(output, expected));
	else
		assert(len == 0);
	if (!show_keys)
		assert(!os_strstr(output, key_hex));
}


int main(int argc, char *argv[])
{
	static const int debug_levels[] = {
		MSG_EXCESSIVE, MSG_MSGDUMP, MSG_DEBUG,
		MSG_INFO, MSG_WARNING, MSG_ERROR
	};
	static const char * const suppressed[] = {
		"WPA: GTK in EAPOL-Key", "WPA: IGTK in EAPOL-Key",
		"WPA: BIGTK in EAPOL-Key", "RSN: received GTK in pairwise handshake",
		"FT: Received GTK in Reassoc Resp", "WPA: KEK", "WPA: KCK",
		"FILS: ICK", "GMK", "Key Counter", "WPA: Decrypted Key Data"
	};
	u8 key[32] = { 0 };
	unsigned int before;
	size_t i;
	int show_keys;

	/* All key bytes in this test are synthetic. Keep dump output quiet. */
	assert(freopen("/dev/null", "w", stdout));
	if (argc > 1)
		assert(wpa_debug_open_file(argv[1]) == 0);
	assert(wpa_debug_level == MSG_INFO);
	assert(wpa_debug_show_keys == 0);
	wpa_msg_register_cb(event_cb);

	expect_event("WPA: PMK", "WPA: PMK", 32);
	expect_event("WPA: PMK", "WPA: PMK", 48);
	expect_event("WPA: PTK", "WPA: PTK", 48);
	expect_event("WPA: PTK", "WPA: PTK", 64);
	expect_event("WPA: PTK", "WPA: PTK", 88);
	expect_event("WPA: TK", "WPA: TK", 16);
	expect_event("WPA: TK", "WPA: TK", 32);
	expect_event("FT: TK", "WPA: TK", 16);
	expect_event("FILS: TK", "WPA: TK", 16);
	expect_event("FILS: Set TK to driver", "WPA: TK", 16);
	expect_event("PASN: TK:", "WPA: TK", 16);
	expect_event("FILS: PMK", "WPA: PMK", 32);
	expect_event("PASN: PMK", "WPA: PMK", 32);
	expect_event("OWE: PMK", "WPA: PMK", 32);
	expect_event("WPA: Group Key", "WPA: GTK", 16);
	expect_event("GTK", "WPA: GTK", 32);
	expect_event("WPA: GTK", "WPA: GTK", 16);
	expect_event("FT: GTK from Reassoc Resp", "WPA: GTK", 16);
	expect_event("WPA: IGTK", "WPA: IGTK", 16);
	expect_event("IGTK", "WPA: IGTK", 32);
	expect_event("FT: IGTK from Reassoc Resp", "WPA: IGTK", 16);
	expect_event("WPA: BIGTK", "WPA: BIGTK", 16);
	expect_event("BIGTK", "WPA: BIGTK", 32);
	expect_event("FT: BIGTK from Reassoc Resp", "WPA: BIGTK", 16);

	before = events;
	for (i = 0; i < ARRAY_SIZE(suppressed); i++)
		wpa_hexdump_key(&context, MSG_DEBUG, suppressed[i], key, sizeof(key));
	assert(events == before);
	wpa_hexdump_key(NULL, MSG_DEBUG, "WPA: GTK", key, sizeof(key));
	wpa_hexdump_key(&context, MSG_DEBUG, "WPA: GTK", NULL, sizeof(key));
	wpa_hexdump_key(&context, MSG_DEBUG, "WPA: GTK", key, 0);
	assert(events == before);

	/* Only ordinary debug dumps follow the verbosity/key-display settings. */
	for (i = 0; i < ARRAY_SIZE(debug_levels); i++) {
		wpa_debug_level = debug_levels[i];
		for (show_keys = 0; show_keys <= 1; show_keys++) {
			wpa_debug_show_keys = show_keys;
			expect_event("WPA: GTK", "WPA: GTK", 16);
		}
	}
	wpa_debug_level = MSG_INFO;
	wpa_debug_show_keys = 0;

	/* Closing the file must not turn off control-interface key events. */
	wpa_debug_close_file();
	expect_event("WPA: GTK", "WPA: GTK", 16);
	expect_debug_dump(0, MSG_INFO, NULL);
	expect_debug_dump(1, MSG_INFO, NULL);
	expect_debug_dump(0, MSG_DEBUG, "[REMOVED]");
	expect_debug_dump(1, MSG_DEBUG,
			  "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
	wpa_msg_register_cb(NULL);
	fprintf(stderr, "key-event tests passed (%u events)\n", events);
	return 0;
}
