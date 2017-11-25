/*
 ============================================================================
 Name        : egihash_test.cpp
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
#include <tuple>
#include <random>
#include <boost/filesystem.hpp>

#define BOOST_TEST_MODULE libegihash_unit_tests
#include <boost/test/unit_test.hpp>

using namespace std;
using byte = uint8_t;
using bytes = std::vector<byte>;
namespace fs = boost::filesystem;


namespace
{
	bool dag_progress(::std::size_t step, ::std::size_t max, int phase)
	{
		switch(phase)
		{
			case cache_seeding:
				cout << "\rSeeding cache...";
				break;
			case cache_generation:
				cout << "\rGenerating cache...";
				break;
			case cache_saving:
				cout << "\rSaving cache...";
				break;
			case cache_loading:
				cout << "\rLoading cache...";
				break;
			case dag_generation:
				cout << "\rGenerating DAG...";
				break;
			case dag_saving:
				cout << "\rSaving DAG...";
				break;
			case dag_loading:
				cout << "\rLoading DAG...";
				break;
			default:
				break;
		}

		cout << fixed << setprecision(2)
			<< static_cast<double>(step) / static_cast<double>(max) * 100.0 << "%"
			<< setfill(' ') << setw(80) << "\r" << endl;

		return true;
	};

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
}

using HashTrait256 = HashTrait<egihash_h256_t, 256, egihash_h256_compute>;
using HashTrait512 = HashTrait<egihash_h512_t, 512, egihash_h512_compute>;

BOOST_AUTO_TEST_SUITE(TODO_name_a_test_suite);

BOOST_AUTO_TEST_CASE(SHA3256) {
	test_hash_func<HashTrait256>();
}

BOOST_AUTO_TEST_CASE(SHA3512) {
	test_hash_func<HashTrait512>();
}

BOOST_AUTO_TEST_CASE(EGIHASH_HASHIMOTO)
{
	using namespace std;
	using namespace egihash;

	if (!boost::filesystem::exists( "data/egihash.dag" ))
	{
		std::cout << "data/egihash.dag does not exist yet! will be auto generated" << std::endl;
		egihash::dag_t dag(0, dag_progress);
		dag.save("data/egihash.dag");
	}

	dag_t d("data/egihash.dag", dag_progress);
	cout << endl;

	string rawdata("this is a test string to be hashed");
	std::vector<std::tuple<uint64_t, std::string, std::string>> vExpected = {
	  std::make_tuple(0x7c7c597c, "e85cb09f99553758a8a794633c93ed25318e2f2839b3a85328e775220ab0a14d", "deafd12b8f35f15b2cac9455ee4f32620cea6727e18e21a81b196633a74d6018")
	 ,std::make_tuple(0xFFFFFFFF00000000, "c2005aa32d527dcbce043648eb04d818be68c8649d353d29eb3c9d5d15927a25", "b0d1c89335fafb7b8c9591fc58623ddf342977cffec88d8d84f14bbfe6f4f651")
	 ,std::make_tuple(1234567890, "1e884b98b307fa44e7ba1d015f6fab47303ac41d04638076479421ea91ea633a", "af969a99b8ee5934b9598a646361675c3b7b8783754e011edd9eb9a702c7711a")
	};

	for ( auto const & expected : vExpected )
	{
		for(auto i = 0; i < 2; ++i)
		{
			auto const h = i == 0 ? full::hash(d, h256_t(rawdata.c_str(), rawdata.size()), std::get<0>(expected)) : light::hash(d.get_cache(), h256_t(rawdata.c_str(), rawdata.size()), std::get<0>(expected));
			auto const value_str = toHex(h.value.b, h.value.hash_size);
			auto const mix_str = toHex(h.mixhash.b, h.mixhash.hash_size);
			BOOST_CHECK_MESSAGE(value_str == std::get<1>(expected), "\nnounce=" << std::get<0>(expected) << "\nactual=" << value_str << "\nexpected=" << std::get<1>(expected));
			BOOST_CHECK_MESSAGE(mix_str == std::get<2>(expected), "\nnounce=" << std::get<0>(expected) << "\nactual=" << mix_str << "\nexpected=" << std::get<2>(expected));
		}
	}

	d.unload();
}


BOOST_AUTO_TEST_CASE(FULL_CLIENT)
{
	string filename_egi = string("egihash.dag");
	string filename_et = string("ethash_eg_seed_2_hashes.dag");
	fs::path egiDagPath = fs::current_path() / "data" / filename_egi;
	fs::path etDagPath = fs::current_path() / "data" / filename_et;

	BOOST_ASSERT(16776896 == egihash::cache_t::get_cache_size(0));
	BOOST_ASSERT(1073739904 == egihash::dag_t::get_full_size(0));

	if ( !boost::filesystem::exists( egiDagPath ) )
	{
		egihash::dag_t dag(0, dag_progress);
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
		constexpr uint32_t DATA_TO_READ = 1024;
		std::unique_ptr<uint8_t[]> buffer_eg (new uint8_t[BUFFER_SIZE]);
		std::unique_ptr<uint8_t[]> buffer_et (new uint8_t[BUFFER_SIZE]);

		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), egiDagSizeSkip);
		dag_eghash_if.read(reinterpret_cast<char*>(buffer_eg.get()), DATA_TO_READ);
		dag_ethash_if.read(reinterpret_cast<char*>(buffer_et.get()), DATA_TO_READ);
		auto eg_read = dag_eghash_if.gcount(), et_read = dag_ethash_if.gcount();
		BOOST_ASSERT(eg_read == DATA_TO_READ);
		BOOST_ASSERT(eg_read == et_read);
		BOOST_ASSERT( ( dag_eghash_if.eof() && dag_ethash_if.eof()) || ( !dag_eghash_if.eof()&& !dag_ethash_if.eof() ) );
		BOOST_ASSERT( 0 == ::std::memcmp(buffer_et.get(), buffer_eg.get(), eg_read) );
	}
}

BOOST_AUTO_TEST_CASE(SEEDHASH_FILE_NAME_TEST)
{
	auto seedhash = egihash::get_seedhash(0);
	std::cout << egihash::seedhash_to_filename(seedhash) << std::endl;
}

// test that light hashes and full hashes produce the same values
BOOST_AUTO_TEST_CASE(light_hash_vs_full_hash_comparison)
{
	using namespace std;
	using namespace egihash;

	if (!boost::filesystem::exists( "data/egihash.dag" ))
	{
		std::cout << "data/egihash.dag does not exist yet! will be auto generated" << std::endl;
		egihash::dag_t dag(0, dag_progress);
		dag.save("data/egihash.dag");
	}

	dag_t d("data/egihash.dag", dag_progress);
	cache_t c(d.get_cache());
	cout << endl;

	string rawdata("this is a test string to be hashed");
	h256_t firsthash(rawdata.c_str(), rawdata.size());

	for (size_t i = 0; i < 10; i++)
	{
		uint64_t nonce = (*reinterpret_cast<uint64_t *>(&firsthash.b[0])) ^ (*reinterpret_cast<uint64_t *>(&firsthash.b[16]));
		firsthash = h256_t(&firsthash.b[0], firsthash.hash_size);
		auto const lighthash = light::hash(c, firsthash, nonce);
		auto const fullhash = full::hash(d, firsthash, nonce);
		cout << "\r[" << toHex(&firsthash.b[0], firsthash.hash_size) << "," << nonce << "] -> "
			<< "\"" << toHex(&lighthash.value.b[0], lighthash.value.hash_size) << "\" == \""
			<< toHex(&fullhash.value.b[0], fullhash.value.hash_size) << "\"" << endl;

		// check that the hashes are nonempty
		BOOST_ASSERT(lighthash);
		BOOST_ASSERT(fullhash);

		// check the byte for byte value and the mixhash is the same for both light and full hashes
		BOOST_ASSERT(memcmp(&lighthash.value.b[0], &fullhash.value.b[0], (std::min)(lighthash.value.hash_size, fullhash.value.hash_size)) == 0);
		BOOST_ASSERT(memcmp(&lighthash.mixhash.b[0], &fullhash.mixhash.b[0], (std::min)(lighthash.value.hash_size, fullhash.value.hash_size)) == 0);

		// checks operator== for egihash::h256_t
		BOOST_ASSERT(lighthash.value == fullhash.value);
		BOOST_ASSERT(lighthash.mixhash == fullhash.mixhash);

		// checks operator== for egihash::result_t
		BOOST_ASSERT(lighthash == fullhash);
	}

	d.unload();
}

BOOST_AUTO_TEST_SUITE_END();
