// Copyright (c) 2017 Ryan Lucchese
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <stdint.h>

#ifdef __cplusplus

#include <functional>
#include <memory>
#include <vector>

namespace egihash
{
	bool test_function();

	struct cache
	{
		using size_type = ::std::size_t;
		using data_type = ::std::vector<::std::vector<int32_t>>;

		cache(const cache &) = default;
		cache & operator=(cache const &) = default;
		~cache() = default;

		cache() = delete;
		cache(cache &&) = delete;
		cache & operator=(cache &&) = delete;

		cache(uint64_t block_number, ::std::string const & seed);

		uint64_t epoch() const;
		size_type size() const;
		data_type const & data() const;

		static size_type get_cache_size(uint64_t const block_number) noexcept;

		struct impl_t;
		::std::shared_ptr<impl_t> impl;
	};

	struct dag
	{
		using size_type = ::std::size_t;
		using data_type = ::std::vector<::std::vector<int32_t>>;
		using progress_callback_type = ::std::function<size_type (size_type)>;

		dag(dag const &) = default;
		dag & operator=(dag const &) = default;
		~dag() = default;

		dag() = delete;
		dag(dag &&) = delete;
		dag & operator=(dag &&) = delete;

		dag(uint64_t const block_number, progress_callback_type = [](size_type){ return 0; });
		dag(::std::string const & file_path);

		uint64_t epoch() const;
		size_type size() const;
		data_type const & data() const;
		void save(::std::string const & file_path) const;

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

EGIHASH_NAMESPACE(light_t) EGIHASH_NAMESPACE(light_new)(unsigned int block_number);
EGIHASH_NAMESPACE(result_t) EGIHASH_NAMESPACE(light_compute)(EGIHASH_NAMESPACE(light_t) light, EGIHASH_NAMESPACE(h256_t) header_hash, uint64_t nonce);
void EGIHASH_NAMESPACE(light_delete)(EGIHASH_NAMESPACE(light_t) light);

EGIHASH_NAMESPACE(full_t) EGIHASH_NAMESPACE(full_new)(EGIHASH_NAMESPACE(light_t) light, EGIHASH_NAMESPACE(callback) callback);
uint64_t EGIHASH_NAMESPACE(full_dag_size)(EGIHASH_NAMESPACE(full_t) full);
void const * EGIHASH_NAMESPACE(full_dag)(EGIHASH_NAMESPACE(full_t) full);
EGIHASH_NAMESPACE(result_t) EGIHASH_NAMESPACE(full_compute)(EGIHASH_NAMESPACE(full_t) full, EGIHASH_NAMESPACE(h256_t) header_hash, uint64_t nonce);
void EGIHASH_NAMESPACE(full_delete)(EGIHASH_NAMESPACE(full_t) full);

void egihash_h256_compute(EGIHASH_NAMESPACE(h256_t) * output_hash, void * input_data, uint64_t input_size);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
