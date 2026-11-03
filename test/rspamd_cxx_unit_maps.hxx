/*
 * Copyright 2026 Alexander Moisseev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Unit tests for maps helpers */

#ifndef RSPAMD_RSPAMD_CXX_UNIT_MAPS_HXX
#define RSPAMD_RSPAMD_CXX_UNIT_MAPS_HXX

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include <vector>
#include <utility>
#include <string>
#include <cstring>

#include "rspamd.h"
#include "libcryptobox/cryptobox.h"
#include "libserver/cfg_file.h"
#include "libserver/maps/map_helpers.h"
#include "libserver/maps/map_private.h"

/* Declared non-static in src/libserver/maps/map.c for unit testing */
extern "C" char *rspamd_map_uri_redacted(const char *uri);

TEST_SUITE("rspamd_maps")
{

	TEST_CASE("rspamd_map_uri_redacted")
	{
		std::vector<std::pair<std::string, std::string>> cases{
			/* No scheme separator: returned verbatim */
			{"not-a-url", "not-a-url"},
			{"/etc/rspamd/list.map", "/etc/rspamd/list.map"},
			/* No userinfo: returned verbatim */
			{"http://example.com/path", "http://example.com/path"},
			{"http://example.com:8080/path", "http://example.com:8080/path"},
			{"http://[::1]:8080/path", "http://[::1]:8080/path"},
			{"http://[::1]/path", "http://[::1]/path"},
			/* Userinfo redacted */
			{"http://user:pass@example.com/path", "http://***@example.com/path"},
			{"http://user@example.com/path", "http://***@example.com/path"},
			{"http://@example.com/path", "http://***@example.com/path"},
			{"https://u:p@host:8443/p?q#f", "https://***@host:8443/p?q#f"},
			{"https://u:p@host", "https://***@host"},
			/* IPv6 host literal is preserved (it follows the userinfo) */
			{"http://user:pass@[::1]:8080/path", "http://***@[::1]:8080/path"},
			{"http://u:p@[2001:db8::1]/path", "http://***@[2001:db8::1]/path"},
			/* Malformed input with several '@': redact up to the last one */
			{"http://a@b:p@host/path", "http://***@host/path"},
			/* '@' outside of the authority (in path / query) must not be touched */
			{"http://host/path@x", "http://host/path@x"},
			{"http://host?u@p", "http://host?u@p"},
		};

		for (const auto &c: cases) {
			SUBCASE(("redact " + c.first).c_str())
			{
				auto *out = rspamd_map_uri_redacted(c.first.c_str());
				CHECK(std::string{out} == c.second);
				g_free(out);
			}
		}
	}

	TEST_CASE("regexp map skips an invalid regexp given twice")
	{
		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));

		auto *re_map = rspamd_map_helper_new_regexp(&map, (enum rspamd_regexp_map_flags) 0);

		/* The second line used to read the value the first one never stored, and crash */
		rspamd_map_helper_insert_re(re_map, "[invalid", "1");
		rspamd_map_helper_insert_re(re_map, "[invalid", "2");
		rspamd_map_helper_insert_re(re_map, "^valid$", "3");

		auto *found = (const char *) rspamd_match_regexp_map_single(re_map, "valid", 5);
		REQUIRE(found != nullptr);
		CHECK(std::string{found} == "3");
		CHECK(rspamd_match_regexp_map_single(re_map, "[invalid", 8) == nullptr);

		rspamd_map_helper_destroy_regexp(re_map);
	}

	TEST_CASE("regexp map leaves out an invalid regexp")
	{
		/* On x86, finalising the map reads the CPU flags from the config */
		struct rspamd_external_libs_ctx libs_ctx;
		memset(&libs_ctx, 0, sizeof(libs_ctx));
		libs_ctx.crypto_ctx = rspamd_cryptobox_init();
		auto *cfg = rspamd_config_new(RSPAMD_CONFIG_INIT_DEFAULT);
		cfg->libs_ctx = &libs_ctx;

		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		map.cfg = cfg;
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));

		struct map_cb_data cbd;
		memset(&cbd, 0, sizeof(cbd));
		cbd.map = &map;

		char data[] = "[invalid\n^valid$\n";
		rspamd_regexp_list_read_single(data, sizeof(data) - 1, &cbd, TRUE);
		void *re_map = nullptr;
		rspamd_regexp_list_fin(&cbd, &re_map);
		REQUIRE(re_map != nullptr);

		/*
		 * The key of the invalid regexp used to stay in the map with no value:
		 * it was counted, and walking the map (WebUI, map:foreach) crashed on it
		 */
		CHECK(map.nelts == 1);

		int nkeys = 0;
		auto count_key = [](gconstpointer, gconstpointer, gsize, gpointer ud) -> gboolean {
			(*(int *) ud)++;
			return TRUE;
		};
		map.traverse_function(re_map, count_key, &nkeys, FALSE);
		CHECK(nkeys == 1);

		rspamd_map_helper_destroy_regexp((struct rspamd_regexp_map_helper *) re_map);
		cfg->libs_ctx = nullptr;
		rspamd_config_free(cfg);
	}

	TEST_CASE("kv list keeps a line that a chunk ends in")
	{
		/*
		 * read_map_file_chunks passes a file map in chunks and gives back
		 * what the parser returns as unread with the next one. A chunk that
		 * ended after a line's key used to lose that key: the line was
		 * dropped ("empty or invalid key found on line 0").
		 */
		const std::string data =
			"# comment\n"
			"alpha.example ONE\n"
			"\"quoted key\" TWO\n"
			"beta.example\tTHREE # comment\n"
			"keyonly.example\n"
			"gamma.example    FOUR\n";
		const std::vector<std::pair<std::string, std::string>> expected{
			{"alpha.example", "ONE"},
			{"quoted key", "TWO"},
			{"beta.example", "THREE"},
			{"keyonly.example", ""},
			{"gamma.example", "FOUR"},
		};

		struct rspamd_map map;
		memset(&map, 0, sizeof(map));
		map.name = (char *) "test";
		rspamd_strlcpy(map.tag, "test", sizeof(map.tag));

		for (std::size_t split = 1; split < data.size(); split++) {
			CAPTURE(split);
			struct map_cb_data cbd;
			memset(&cbd, 0, sizeof(cbd));
			cbd.map = &map;

			/* The first chunk, then what it left unread plus the rest */
			std::string first = data.substr(0, split);
			char *pos = rspamd_kv_list_read(first.data(), first.size(), &cbd, FALSE);
			std::string second;

			/* As read_map_file_chunks: kept only if inside the chunk */
			if (pos && pos > first.data() && pos < first.data() + first.size()) {
				second.assign(pos, first.data() + first.size());
			}

			second += data.substr(split);
			rspamd_kv_list_read(second.data(), second.size(), &cbd, TRUE);

			void *target = nullptr;
			rspamd_kv_list_fin(&cbd, &target);
			REQUIRE(target != nullptr);
			auto *htb = (struct rspamd_hash_map_helper *) target;

			CHECK(map.nelts == expected.size());

			for (const auto &[k, v]: expected) {
				CAPTURE(k);
				auto *found = (const char *) rspamd_match_hash_map(htb, k.data(), k.size());
				REQUIRE(found != nullptr);
				CHECK(std::string{found} == v);
			}

			rspamd_map_helper_destroy_hash(htb);
		}
	}
}

#endif
