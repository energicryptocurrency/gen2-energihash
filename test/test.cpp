/*
 ============================================================================
 Name        : test.c
 Author      : Ranjeet Devgun
 Version     :
 Copyright   : TODO Copyright notice
 Description : Uses shared library to print greeting
               To run the resulting executable the LD_LIBRARY_PATH must be
               set to ${project_loc}/libegihash/.libs
               Alternatively, libtool creates a wrapper shell script in the
               build directory of this program which can be used to run it.
               Here the script will be called test.
 ============================================================================
 */

#include <cstdint>
#include <iomanip>
#include "egihash.h"


#ifdef _WIN32
#include <windows.h>
#include <Shlobj.h>
#endif



#include <iostream>
#include <functional>
#include <fstream>
#include <vector>
#include <memory>
#include <random>
#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;
using byte = uint8_t;
using bytes = std::vector<byte>;
namespace fs = boost::filesystem;


std::string toHex(const uint8_t *streamBytes, const uint64_t size)
{
	std::stringstream sHex;
	for( uint64_t iter = 0; iter < size; ++iter )
	{
		sHex << std::nouppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(streamBytes[iter]);
	}
	return sHex.str();
}

template <typename HashType
, size_t HashSize
, void (*Compute)(HashType * output_hash, void * input_data, uint64_t input_size)>
struct HashTrait
{
	static constexpr size_t Size = HashSize;
	static constexpr decltype(Compute) compute = Compute;
	using Type = HashType;
};


template<typename HashTrait>
void test_hash_func()
{
	string filename = string("hashcache_") + std::to_string(HashTrait::Size) + ".csv";
	    fs::path hcPath = fs::current_path() / "data" / filename;
	#ifdef TEST_DATA_DIR
	    if (!fs::exists(hcPath))
	    {
	    	hcPath = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
	    }
	#endif
	    cout << hcPath.string() << endl;
		ifstream hif(hcPath.string().c_str());
		BOOST_REQUIRE_MESSAGE(hif.is_open(), "hash cache missing?");
		if ( hif.is_open() )
		{
			char buffer[1024] = {0};
			while(hif.getline(buffer, sizeof(buffer)))
			{
				string line = buffer;
				auto index = line.find_first_of(',');
				auto hashSource = line.substr(0, index), hashExpected = line.substr(index + 1);
				if ( hashSource.size() == HashTrait::Size / 8 && hashExpected.size() == HashTrait::Size / 4 )
				{
					typename HashTrait::Type input;
					typename HashTrait::Type hashRaw;
					memcpy(&input, hashSource.c_str(), HashTrait::Size / 8);
					HashTrait::compute(&hashRaw, input.b, HashTrait::Size / 8);
					auto actual = toHex((uint8_t*)&hashRaw, HashTrait::Size / 8);
					//cout << hashSource << "," << actual << endl;
					BOOST_REQUIRE_MESSAGE(hashExpected == actual, "\nsource: " << hashSource << "\nexpected: " << hashExpected.c_str() << "\n" << "actual: " << actual.c_str() << "\n");
				}
			}
		}
}

using HashTrait256 = HashTrait<egihash_h256_t, 256, egihash_h256_compute>;
using HashTrait512 = HashTrait<egihash_h512_t, 512, egihash_h512_compute>;


BOOST_AUTO_TEST_CASE(SHA3256) {
	test_hash_func<HashTrait256>();
}

BOOST_AUTO_TEST_CASE(SHA3512) {
	test_hash_func<HashTrait512>();
}

BOOST_AUTO_TEST_CASE(FULL_CLIENT)
{
	string filename_egi = string("egihash.dag");
	string filename_et = string("ethash_eg_seed_2_hashes.dag");
	fs::path egiDagPath = fs::current_path() / "data" / filename_egi;
	fs::path etDagPath = fs::current_path() / "data" / filename_et;

	cout << egihash::cache_t::get_cache_size(0) << endl;
	cout << egihash::dag_t::get_full_size(0) << endl;
	BOOST_ASSERT(16776896 == egihash::cache_t::get_cache_size(0));
	BOOST_ASSERT(1073739904 == egihash::dag_t::get_full_size(0));

	if ( !boost::filesystem::exists( egiDagPath ) )
	{
		auto progress = [](::std::size_t step, ::std::size_t max, int phase) -> bool
		{
			switch(phase)
			{
				case egihash::cache_seeding:
					cout << "Seeding cache..." << endl;
					break;
				case egihash::cache_generation:
					cout << "Generating cache..." << endl;
					break;
				case egihash::cache_saving:
					cout << "Saving cache..." << endl;
					break;
				case egihash::cache_loading:
					cout << "Loading cache..." << endl;
					break;
				case egihash::dag_generation:
					cout << "Generating DAG..." << endl;
					break;
				case egihash::dag_saving:
					cout << "Saving DAG..." << endl;
					break;
				case egihash::dag_loading:
					cout << "Loading DAG..." << endl;
					break;
				default:
					break;
			}

			cout << fixed << setprecision(2)
			<< static_cast<double>(step) / static_cast<double>(max) * 100.0 << "%"
			<< setfill(' ') << setw(80) << flush;

			return true;
		};
		egihash::dag_t dag(0, progress);
		dag.save(egiDagPath.string());
	}

	// File should be byte by byte same:
	ifstream dag_ethash_if(etDagPath.string().c_str(), std::ios_base::binary);
	ifstream dag_eghash_if(egiDagPath.string().c_str(), std::ios_base::binary);
	BOOST_ASSERT(dag_ethash_if.is_open() && dag_eghash_if.is_open());
	if ( dag_ethash_if.is_open() && dag_eghash_if.is_open() )
	{
		uint64_t egiDagSizeSkip = sizeof(egihash::constants::DAG_MAGIC_BYTES) +
					sizeof(egihash::constants::MAJOR_VERSION) +
					sizeof(egihash::constants::REVISION) +
					sizeof(egihash::constants::MINOR_VERSION) +
					sizeof(uint64_t) + // epoch
					sizeof(uint64_t) + // cache begin
					sizeof(uint64_t) + // cache_end
					sizeof(uint64_t) + // dag_begin
					sizeof(uint64_t);// dag_end

		egiDagSizeSkip += egihash::cache_t::get_cache_size(0);

		cout << egiDagSizeSkip << endl;
		constexpr uint32_t BUFFER_SIZE = 32 * 1024 * 1024;
		constexpr uint32_t HASH_BYTES = 64;
		constexpr uint32_t DATA_TO_READ = HASH_BYTES * 2;
		std::unique_ptr<uint8_t[]> buffer_eg (new uint8_t[BUFFER_SIZE]);
		std::unique_ptr<uint8_t[]> buffer_et (new uint8_t[BUFFER_SIZE]);

		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), egiDagSizeSkip);
		dag_ethash_if.read(reinterpret_cast<char*>(buffer_et.get()), 8); // ETHash DAG header size is 8 bytes

		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), DATA_TO_READ);
		dag_ethash_if.read(reinterpret_cast<char*>(buffer_et.get()), DATA_TO_READ);
		auto eg_read = dag_eghash_if.gcount(), et_read = dag_ethash_if.gcount();
		BOOST_ASSERT(eg_read == DATA_TO_READ);
		BOOST_ASSERT(eg_read == et_read);
		BOOST_ASSERT( ( dag_eghash_if.eof() && dag_ethash_if.eof()) || ( !dag_eghash_if.eof()&& !dag_ethash_if.eof() ) );
		auto max_iter = std::min( static_cast<uint32_t>(eg_read) / HASH_BYTES, 2U);
		for ( uint32_t iter = 0; iter < max_iter; ++iter)
		{
			cout << "EGIHASH: "<< toHex(buffer_eg.get() + iter * HASH_BYTES, HASH_BYTES) << endl;
			cout << "ETHASH: " << toHex(buffer_et.get() + iter * HASH_BYTES, HASH_BYTES) << endl;
		}
		BOOST_ASSERT( 0 == ::std::memcmp(buffer_et.get(), buffer_eg.get(), eg_read) );
	}
}


/*BOOST_AUTO_TEST_CASE(GENESIS_BLOCK_HASH_TEST)
{
	string filename_egi = string("egihash.dag");
	fs::path egiDagPath = fs::current_path() / "data" / filename_egi;

	cout << egihash::cache_t::get_cache_size(0) << endl;
	cout << egihash::dag_t::get_full_size(0) << endl;
	BOOST_ASSERT(16776896 == egihash::cache_t::get_cache_size(0));
	BOOST_ASSERT(1073739904 == egihash::dag_t::get_full_size(0));

	if ( !boost::filesystem::exists( egiDagPath ) )
	{
		auto progress = [](::std::size_t step, ::std::size_t max, int phase) -> bool
		{
			switch(phase)
			{
				case egihash::cache_seeding:
					cout << "Seeding cache..." << endl;
					break;
				case egihash::cache_generation:
					cout << "Generating cache..." << endl;
					break;
				case egihash::cache_saving:
					cout << "Saving cache..." << endl;
					break;
				case egihash::cache_loading:
					cout << "Loading cache..." << endl;
					break;
				case egihash::dag_generation:
					cout << "Generating DAG..." << endl;
					break;
				case egihash::dag_saving:
					cout << "Saving DAG..." << endl;
					break;
				case egihash::dag_loading:
					cout << "Loading DAG..." << endl;
					break;
				default:
					break;
			}

			cout << fixed << setprecision(2)
			<< static_cast<double>(step) / static_cast<double>(max) * 100.0 << "%"
			<< setfill(' ') << setw(80) << flush;

			return true;
		};
		egihash::dag_t dag(0, progress);
		dag.save(egiDagPath.string());
	}

	ifstream dag_eghash_if(egiDagPath.string().c_str(), std::ios_base::binary);
	BOOST_ASSERT(dag_eghash_if.is_open());
	if ( dag_eghash_if.is_open() )
	{
		uint64_t egiDagSizeSkip = sizeof(egihash::constants::DAG_MAGIC_BYTES) +
					sizeof(egihash::constants::MAJOR_VERSION) +
					sizeof(egihash::constants::REVISION) +
					sizeof(egihash::constants::MINOR_VERSION) +
					sizeof(uint64_t) + // epoch
					sizeof(uint64_t) + // cache begin
					sizeof(uint64_t) + // cache_end
					sizeof(uint64_t) + // dag_begin
					sizeof(uint64_t);// dag_end

		egiDagSizeSkip += egihash::cache_t::get_cache_size(0);

		cout << egiDagSizeSkip << endl;
		constexpr uint32_t BUFFER_SIZE = 32 * 1024 * 1024;
		constexpr uint32_t HASH_BYTES = 64;
		constexpr uint32_t DATA_TO_READ = HASH_BYTES * 2;
		std::unique_ptr<uint8_t[]> buffer_eg (new uint8_t[BUFFER_SIZE]);
		std::unique_ptr<uint8_t[]> buffer_et (new uint8_t[BUFFER_SIZE]);

		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), egiDagSizeSkip);
		dag_ethash_if.read(reinterpret_cast<char*>(buffer_et.get()), 8); // ETHash DAG header size is 8 bytes

		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), DATA_TO_READ);
		dag_ethash_if.read(reinterpret_cast<char*>(buffer_et.get()), DATA_TO_READ);
		auto eg_read = dag_eghash_if.gcount(), et_read = dag_ethash_if.gcount();
		BOOST_ASSERT(eg_read == DATA_TO_READ);
		BOOST_ASSERT(eg_read == et_read);
		BOOST_ASSERT( ( dag_eghash_if.eof() && dag_ethash_if.eof()) || ( !dag_eghash_if.eof()&& !dag_ethash_if.eof() ) );
		auto max_iter = std::min( static_cast<uint32_t>(eg_read) / HASH_BYTES, 2U);
		for ( uint32_t iter = 0; iter < max_iter; ++iter)
		{
			cout << "EGIHASH: "<< toHex(buffer_eg.get() + iter * HASH_BYTES, HASH_BYTES) << endl;
			cout << "ETHASH: " << toHex(buffer_et.get() + iter * HASH_BYTES, HASH_BYTES) << endl;
		}
		BOOST_ASSERT( 0 == ::std::memcmp(buffer_et.get(), buffer_eg.get(), eg_read) );
	}
}*/


