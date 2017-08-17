// Copyright (c) 2017 Ryan Lucchese
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <stdint.h>

#ifdef __cplusplus

#include <functional>
#include <memory>
#include <type_traits>
#include <vector>

namespace egihash
{
	bool test_function();

	// TODO: randomized seedhash not zero seedhash
	static constexpr char epoch0_seedhash[] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	static_assert(sizeof(epoch0_seedhash) == 33, "Invalid seedhash");
	::std::string get_seedhash(uint64_t const block_number);

	struct h256_t
	{
		h256_t();
		// TODO: copy/move ctors/operators & operator bool()
		uint8_t b[32];
	};

	struct result_t
	{
		result_t() = default;
		// TODO: copy/move ctors/operators & operator bool()
		h256_t value;
		h256_t mixhash;
	};

	enum progress_callback_phase
	{
		cache_seeding,
		cache_generation,
		cache_saving,
		cache_loading,
		dag_generation,
		dag_saving,
		dag_loading
	};

	using progress_callback_type = ::std::function<bool (::std::size_t /* step */, ::std::size_t /* max */, progress_callback_phase /* phase */)>;

	struct cache_t
	{
		using size_type = ::std::size_t;
		using data_type = ::std::vector<::std::vector<int32_t>>;

		cache_t(const cache_t &) = default;
		cache_t & operator=(cache_t const &) = default;
		cache_t(cache_t &&) = default;
		cache_t & operator=(cache_t &&) = default;
		~cache_t() = default;

		cache_t() = delete;

		cache_t(uint64_t block_number, ::std::string const & seed, progress_callback_type = [](size_type, size_type, int){ return true; });

		uint64_t epoch() const;
		size_type size() const;
		data_type const & data() const;
		void load(::std::function<bool(void *, size_type)> read);

		static size_type get_cache_size(uint64_t const block_number) noexcept;

		struct impl_t;
		::std::shared_ptr<impl_t> impl;
	};

	struct dag
	{
		using size_type = ::std::size_t;
		using data_type = ::std::vector<::std::vector<int32_t>>;

		dag(dag const &) = default;
		dag & operator=(dag const &) = default;
		dag(dag &&) = default;
		dag & operator=(dag &&) = default;
		~dag() = default;

		dag() = delete;

		dag(uint64_t const block_number, progress_callback_type = [](size_type, size_type, int){ return true; });
		dag(::std::string const & file_path);

		uint64_t epoch() const;
		size_type size() const;
		data_type const & data() const;
		void save(::std::string const & file_path) const;

		cache_t get_cache() const;

		static size_type get_full_size(uint64_t const block_number) noexcept;

		struct impl_t;
		::std::shared_ptr<impl_t> impl;
	};
}

extern "C"
{
#endif // __cplusplus

#define EGIHASH_NAMESPACE_PREFIX egihash
#define EGIHASH_CONCAT(x, y) EGIHASH_CONCAT_(x, y)
#define EGIHASH_CONCAT_(x, y) x ## y
#define EGIHASH_NAMESPACE(name) EGIHASH_NAMESPACE_(_ ## name)
#define EGIHASH_NAMESPACE_(name) EGIHASH_CONCAT(EGIHASH_NAMESPACE_PREFIX, name)

typedef int (* EGIHASH_NAMESPACE(callback))(unsigned int);
typedef struct EGIHASH_NAMESPACE(light) * EGIHASH_NAMESPACE(light_t);
typedef struct EGIHASH_NAMESPACE(full) * EGIHASH_NAMESPACE(full_t);
typedef struct EGIHASH_NAMESPACE(h256) { uint8_t b[32]; } EGIHASH_NAMESPACE(h256_t);
typedef struct EGIHASH_NAMESPACE(result) { EGIHASH_NAMESPACE(h256_t) value; EGIHASH_NAMESPACE(h256_t) mixhash; } EGIHASH_NAMESPACE(result_t);

#if 0 // TODO: FIXME
EGIHASH_NAMESPACE(light_t) EGIHASH_NAMESPACE(light_new)(unsigned int block_number);
EGIHASH_NAMESPACE(result_t) EGIHASH_NAMESPACE(light_compute)(EGIHASH_NAMESPACE(light_t) light, EGIHASH_NAMESPACE(h256_t) header_hash, uint64_t nonce);
void EGIHASH_NAMESPACE(light_delete)(EGIHASH_NAMESPACE(light_t) light);

EGIHASH_NAMESPACE(full_t) EGIHASH_NAMESPACE(full_new)(EGIHASH_NAMESPACE(light_t) light, EGIHASH_NAMESPACE(callback) callback);
uint64_t EGIHASH_NAMESPACE(full_dag_size)(EGIHASH_NAMESPACE(full_t) full);
void const * EGIHASH_NAMESPACE(full_dag)(EGIHASH_NAMESPACE(full_t) full);
EGIHASH_NAMESPACE(result_t) EGIHASH_NAMESPACE(full_compute)(EGIHASH_NAMESPACE(full_t) full, EGIHASH_NAMESPACE(h256_t) header_hash, uint64_t nonce);
void EGIHASH_NAMESPACE(full_delete)(EGIHASH_NAMESPACE(full_t) full);

void egihash_h256_compute(EGIHASH_NAMESPACE(h256_t) * output_hash, void * input_data, uint64_t input_size);
#endif

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
