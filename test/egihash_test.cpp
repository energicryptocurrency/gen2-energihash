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
#include <boost/tokenizer.hpp>

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
		using namespace egihash;

		// saving output for longer running tasks like DAG generation
		switch (phase)
		{
			case cache_saving:
			case cache_loading:
			case dag_saving:
			case dag_loading:
				return true;
			default:
				break;
		}

		switch (phase)
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
			<< setfill(' ') << setw(80) << flush;

		if (step == max) cout << "\r" << endl;

		return true;
	};

	template<typename HashType>
	void test_hash_func()
	{
		string filename = string("hashcache_") + std::to_string(HashType::hash_size * 8) + ".csv";
			fs::path hcPath = fs::current_path() / "data" / filename;
		#ifdef TEST_DATA_DIR
			if (!fs::exists(hcPath))
			{
				hcPath = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
			}
		#endif
			ifstream hif(hcPath.string().c_str());
			BOOST_REQUIRE_MESSAGE(hif.is_open(), "hash cache missing?");
			if ( hif.is_open() )
			{
				char buffer[1024] = {0};
				size_t lineCount = 1;
				while(hif.getline(buffer, sizeof(buffer)))
				{
					string line = buffer;
					auto index = line.find_first_of(',');
					auto hashSource = line.substr(0, index), hashExpected = line.substr(index + 1);
					BOOST_REQUIRE_MESSAGE(hashSource.size() == HashType::hash_size, "\ninvalid hash source at line: " << lineCount);
					BOOST_REQUIRE_MESSAGE(hashExpected.size() == (HashType::hash_size * 2), "\ninvalid expected hash entry at line: " << lineCount);
					auto actual = HashType(hashSource.c_str(), hashSource.length()).to_hex();
					BOOST_REQUIRE_MESSAGE(hashExpected == actual, "\nsource: " << hashSource << "\nexpected: " << hashExpected.c_str() << "\n" << "actual: " << actual.c_str() << "\n");
					lineCount++;
				}
			}
	}

	egihash::h256_t HashFromHex(std::string const & hex)
	{
		using namespace egihash;
		h256_t ret;
		for (size_t i = 0; i < 32; i++)
		{
			auto const ptr = hex.c_str();
			char hexpair[] = { ptr[i*2], ptr[i*2 + 1] };
			ret.b[i] = static_cast<uint8_t>(stoi(hexpair, nullptr, 16));
		}
		return ret;
	}
}

BOOST_AUTO_TEST_SUITE(Keccak);

BOOST_AUTO_TEST_CASE(Keccak_256)
{
	test_hash_func<egihash::h256_t>();
}

BOOST_AUTO_TEST_CASE(Keccak_512)
{
	test_hash_func<egihash::h512_t>();
}

BOOST_AUTO_TEST_SUITE_END();


BOOST_AUTO_TEST_SUITE(Egihash);

BOOST_AUTO_TEST_CASE(EGIHASH_HASHIMOTO)
{
	using namespace std;
	using namespace egihash;

	if (!boost::filesystem::exists( "data/egihash.dag" ))
	{
		egihash::dag_t dag(0, dag_progress);
		dag.save("data/egihash.dag");
	}

	dag_t d("data/egihash.dag", dag_progress);

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
			auto const value_str = h.value.to_hex();
			auto const mix_str = h.mixhash.to_hex();
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

BOOST_AUTO_TEST_CASE(headerhashes)
{
	using namespace std;
	using namespace egihash;

	string filename = string("headerhash_test_vectors.csv");
	fs::path hcPath = fs::current_path() / "data" / filename;
#ifdef TEST_DATA_DIR
	if (!fs::exists(hcPath))
	{
		hcPath = fs::path(BOOST_PP_STRINGIZE(TEST_DATA_DIR)) / filename;
	}
#endif
	ifstream hif(hcPath.string().c_str());
	BOOST_REQUIRE_MESSAGE(hif.is_open(), "Can not read data file headerhash_test_vectors.csv");

	auto tokenize_line = [](std::string const & line) -> std::vector<std::string>
	{
		using namespace boost;
		std::vector<std::string> vec;
		tokenizer<escaped_list_separator<char> > tk(line, escaped_list_separator<char>('\\', ',', '\"'));
		for (tokenizer<escaped_list_separator<char> >::iterator i(tk.begin());i!=tk.end();++i)
		{
			vec.push_back(*i);
		}
		return vec;
	};

	if ( hif.is_open() )
	{
		string line;
		while (getline(hif, line))
		{
			//string line = buffer;
			auto const tokens = tokenize_line(line);
			BOOST_ASSERT(tokens.size() == 5);
			auto const epoch = static_cast<unsigned int>(stoi(tokens[0].c_str()));
			auto const headerhash = HashFromHex(tokens[1]);
			auto const nonce = static_cast<unsigned int>(stoi(tokens[2].c_str()));
			auto const resulthash = HashFromHex(tokens[3]);
			auto const mixhash = HashFromHex(tokens[4]);

			auto const cache = cache_t(epoch * constants::EPOCH_LENGTH);

			// make sure hex conversion is behaving sensibly
			BOOST_REQUIRE_MESSAGE(headerhash.to_hex() == tokens[1], "hash hex conversion failed");

			result_t expected;
			expected.value = resulthash;
			expected.mixhash = mixhash;

			result_t const actual = light::hash(cache, headerhash, nonce);
			BOOST_CHECK_MESSAGE(resulthash == actual.value, "Hash value comparison failed (expected " << resulthash.to_hex() << " got " << actual.value.to_hex() << ")");
			BOOST_CHECK_MESSAGE(mixhash == actual.mixhash, "Mix hash comparison failed (expected " << mixhash.to_hex() << " got " << actual.mixhash.to_hex() << ")");
			BOOST_CHECK_MESSAGE(expected == actual, "Hash result comparison failed");
		}
	}
}

BOOST_AUTO_TEST_CASE(seedhash_test)
{
	using namespace egihash;

	static constexpr char const * first100_seedhashes[] =
	{
		"a8494bb2895bd7ed18bb39b7b28af51dec51f7cad330c168f1bd1c90e7614c32",
		"0b74b050614361a85afec955c4e276623edc002cce1f3c0aab2f93f34ec7499e",
		"714a8ecd802936293b6ad82ba052318ed274874c8f13989809a829237e841892",
		"27cb8dbcc45b40addb1e49400b7853f5f6f65776aa23ce6770dce40af5ce355e",
		"b8c6d43d85e406c78c6a3d7e4111dd01d6da0b2dcde4939d7fae04b4ef19672e",
		"8d39bf554fb2966f40a77625e0bf84f1160a8592d13fed62f5ec45e7002d00e4",
		"2683757934f04d6654d8ab6e8ba435e9f143f15e3ab698c3c727b78bc041a58c",
		"c7e64cf7742fa4f0c0766b41a2c93d9aafc763d69ba322fc4f0696dd13fa3320",
		"7b6035b636b3bc2a2430c43c7a84029f771448ff52b6febe85e232c6f9ca3b64",
		"3e6a51fc33b93cb409a7c09b923544a1e3f56e3410cc502ce81c668c95472538",
		"cf97dbe1f0017726185ffa98f767b3a5bd8afe810ce98e2d34586b635af5c318",
		"610b251d71ab4bc57fad018e20bcdfdb49e74274d80a4063789151f48f27af98",
		"f1fb026f5e49cd4b0cb7995568122e08728c31678bf68d745d0c505f848bf454",
		"352078c0b7c82eb6c62e2564ed0236d095709fad79847652aa9aff373f7eae97",
		"db756caa77d597916a37ecfc3861916ac973b608f403ea3c292442a13e1aa36d",
		"05df22f093d80ffaa37f8b37e4f85e93b2feab1cb0bc729f106887f02b7eb86f",
		"5fa7a8493a557ef2fcd77049839378a06d571364cee26c1d3d4f80ee2685aa62",
		"a900b31d8e3f493a95fa1a731b867e7edd1b2e4bb28ad8ded846e461e744fcd2",
		"aa0e8cdf4cf7f99b9a600bcc320bb823de02604cf6df85875a51e9233edec0b2",
		"fa56ed28830042113cefa23ee779676731c035e88c501823d2e366b636093039",
		"85bc1d7a8ce642984a2f4b351be5dc8ec564a68564c8c6dd77c8f3e9e56d2ec6",
		"cfec63c6946587ad0a173f9f94de1e4242408371b0fbeaf25908fec1c57bea38",
		"03516ee43138f0f4e263e5576ebb35497e97843a129abc7a14c858f1eee3ad8d",
		"2ae5f5db855a2b2fe01237e624a87b8539431680571fed91a0484247c3469dfc",
		"4a1937df43af2337408387716bd2260b642a5b1233a342bd069117bf4fd6391c",
		"1020c92eb9fbd7e8ed5886dd8bc83b0d9f052129bf17c608ddc128f2c3619a3e",
		"d4f2d3d047acffa8385fb9795b2244c0dfeb5e5130d2d730f6e300dfe514de70",
		"04eb0f9c600538b16237b7a5bff297c42d1c9e563e522cc9c5bb4ba04c9c810c",
		"1c13a1c10fe3e4eccdba90b7bad971f891b42e9b17aca9dc5426e1b85b69c4c2",
		"a4858ac4d1f934ee89c22f5bfe6a73ff7e01241c8192391600ed5f1dd8137310",
		"d0a73eee47098ba7cd0b421d54ff2eb0524f4b2920b3bf8c22ce321e45b56bf8",
		"f4f88ed9fc16303b1bb3d4ce191858ace2ffc6023d67b8637ed3e595f1216cc9",
		"06c6e998cef9e1eb1546c7f7db71cdabded80b34143241dd0c07c75e23ae848b",
		"ee9ca223b2e94eeaed16d6f80ffa0856d6bf2327ef6e177bc0265b03422da54b",
		"8e5b832eae668b4a3d49beceae7259f83b3f2a27c765f703e4acd7dd6f5a929b",
		"b802834920f3948e6351d93ebe6937d24ae434ebd5ca6f4d77c192a11dbb66ec",
		"d404efa631a6f01eed418c72217e12f911ba5ce611c04d8e6080b0c84b4b6768",
		"8b54aabf000c4aa428fe04ea91ed4f6859d68d6867b1480f9510ec70f381654d",
		"5268197c54c5ae766c8a490704054563c34a1cb31fa29f7595204ddc6c967c1a",
		"ffabd2cf36d56e47f4beb543f10beeda51a5a514b9765d1f5626ae7088536b4f",
		"67a27b4bdee84137a42cf6b453cc9ac1ed7223770b9f4fca44ae131013a4fe25",
		"9354b15f28a044aad8445eeeb951e6c9519623410ddde28fccd95dfaa1859ce7",
		"527cea9d9b4f422377084c1d9e111e695ac7d1b4f387ccc3c556ded69ceb40d0",
		"2b106356d7c369b7638e43c01e5d625715faa29d9a4a712a4f0214406f66c18c",
		"8010566894b68636a339abb1da0fc058a55b8b6aea7c27f01de867ada1ec8033",
		"d7b42b35d36c2c65c240a8197433acdf103bf004aa0d130bd42635800f298d1a",
		"a358ba41cf3a869e03af5a89b96d9b09f48f1eccd80ff24c90e8209371a9fcf1",
		"3fbeb365f091a104895e63db022f1ffe8bcc2e77d3b6517d3b6419ace972949c",
		"0a10fa3d5a7fc763c3dc949f4447289a4a083a0f9f12beca03d3893636dc6b11",
		"1dd7c5ac509da0050ff16805a6c8bb42cf26dbac25aded19ec5bd8edc9c905de",
		"5c61be74641b9e229ca83bd8e240d89d44a2725f0797d90251212cc12dcc21f6",
		"1f0ea81f20b517a863c3dd242662d5e22976239412d4b549c4afd52d608b5576",
		"135e220b875e3427b6b1fc776e099b2d7a9d86a6ebe96a03196cdbdae3f0d223",
		"d185ef051cc7277eded1e13b69c11e7c8c6ce92ab5580a1f4ad17c6701779271",
		"fc62b4b8b025e32a74803f1c1523c938aeea3c683029fb1d77656a6deceda542",
		"81411dee455ce6f3eaa774f252651fd21b229ff7c078d2ad7af7bf5faf935b20",
		"86cab7dbf05587e90849803a4a65cdfe157afdb0c354a30531daea67ec4ad851",
		"89d28e735e7aae22c8666e259c67a609bf0eb3fd3a7b336fe7e85be4a0344e1f",
		"6b661ea3e2d4e646daddf30ffc5ea0fbd72147f191657caed6b79abdab547238",
		"3e6726fc6df9db16a451286ed7c4f38b650d555773573257d02a785e859d0206",
		"e454b470a306d1783c3b102981a2c81a0c23ebb507f1239e138b7994730c4974",
		"e9eedbc79afd1e51d5b17befaa3c1cc98dfb0557465c8c323c958b57a79c7cde",
		"c9c2448c809fa3e4fad3f98c24ee36e90fe56577a5ef8067e13defd26b0c4830",
		"524189a22dc5ac47453088f691ef0a56a57713ed469ca1e8c6bee92878960f69",
		"c465fa0f490b7409758797d2b24ace35c139813aea48b74ea713dd709641bcf1",
		"76a3b1da2f636307513f3ea010cf5eef9febf571fa58b0b4f9b85dcac3bfed69",
		"e49d7dbd4e1f4182af5e7f7c1e1f8e8e3b6fd87b9eca7b4593e1e669d770071a",
		"2c3e099519a2e5e428048343388296457ec4f7ab2855cfe1d2caafaa5ea28026",
		"e442fdd0732989b0e800579fd957dfd8c9273d28be445c9f661ed93e973767f6",
		"88e49c49a360339187b0d51d11bb424a936c23cee0d425c0bac454393ad798f2",
		"0821473fd962930889a15684faba9476ad53643cc8b02376a79e69f826f27a55",
		"a367ffbeb0f3581b5cc31d1f1e202957ee741242d374c1cdbf90c15c5a0b7ba1",
		"e0ff5135e68d3a2e7e83099ef8a77d6cae2843da5824d24834123d44fbfe42c3",
		"2b182261fa701802f80777e82ed26c12b295db0f9d4c38be9602620863e402fb",
		"454484a49ebc2af66431959220f46483f7a848e10fc1136f3b17c56b18bea438",
		"50febe095d685750f0e8191297d3b4def34fd9124897edbd2233834bb7e5d059",
		"1f2c414d30d5b278617e8fb5cad563b5a64f4d3aa43601cb0148b683e6e74b99",
		"04b52d092cecf05f52b7c2baf22882b0bca8baa243a09edb547dd44ec52b68ae",
		"3b39138f70c009da8121cf88b0431fb3327446b37ada66e2d7e493f3a648a5c0",
		"91e6db67e039647c9d74abeeac7a4f60714632e035893abddd81f449ca75524a",
		"ce5e355929e5f16affa2345c9c36ba83d63bc90850d3c265ed69a83a5f5aea26",
		"6a934e0d79a49439a329412793a00b2e5226da793115be2e4440b002a6de60c9",
		"4b31566354b1f8a694c7c7c7893070ef94ba184254128d0d58bd0acc866d9b2a",
		"6e2ceac1b4ba7dc3e4eb8544ca3d1a83d9f6339840534374099b30e8f9b3792a",
		"c85a807871ad72bae6fa9e404d7e6ca3416bb4283719d08a0b7f721a6930d814",
		"54d1d677e18d68c6dd7c210c819b598f0bd23a6c258b61ae4a47d9491b60c6ba",
		"9623ca38fa26d375a22a859b63d909cf512440e079395b9f2dc3e7921ad1680b",
		"ba20a83b57aa9ef2331f3beead8189e1cc199250dfb669ee8af11e946457dad2",
		"af99256d9b334b0d19cb77546f150ecc20ab47b2575b5c9ad344822f5d54c1de",
		"1c2800186fece92e35f0c9c455ad95cee9aa81c28be1f683c793c0673760939b",
		"63bde9e1a825e7abaafc53b9493c59a7e14e571334389b5e7a4e06a2ca6e4d48",
		"ab954e6c4cc6f48880772d5257db79beff4488a7c084a3d023f47f427e152682",
		"9141c1f8393351776de7f07385d7f810af79e9358f75558a6045bfab81ec20a5",
		"f788ac17949d05847c93d9fb15d4cfc59e98b0fe3a071027729b7847b0f06cb6",
		"0d0e825f1668883554e8d21e74f1433380ca8e240e949e5f34b14f6b5680f182",
		"b01eb592029671e00f0628f34549c85c59cf33e5a8c72758d95cdbf4b00f08bb",
		"3be8472c70181c48172d304d6242356e1711d21db61f7afdced3795b393a050f",
		"5f4dd21e1e604e7844a11a7a94681d744d78f6454966820c5f7ae67159865a2b",
		"dd41a07051a88b82db7c313454924d9b5221c8ba3ea8f2e6209354f7fa235dbf",
		"e4101f3e107b7f810b2b81101a148797701a82320497d0240c8a43a7aa18bf8f"
	};

	// test the first 100 epochs worth of seedhashes
	for (size_t i = 0; i < 100; i++)
	{
		BOOST_ASSERT(cache_t::get_seedhash(i * constants::EPOCH_LENGTH).to_hex() == std::string(first100_seedhashes[i]));
	}

	// test that all block numbers up to the first EPOCH_LENGTH return the first epoch seedhash
	auto const first_hash = std::string(first100_seedhashes[0]);
	for (size_t i = 0; i < constants::EPOCH_LENGTH; i++)
	{
		BOOST_ASSERT(cache_t::get_seedhash(i).to_hex() == first_hash);
	}

	// test that all block numbers from the second EPOCH_LENGTH to the third epoch return the second epoch seedhash
	auto const second_hash = std::string(first100_seedhashes[1]);
	for (size_t i = constants::EPOCH_LENGTH; i < (constants::EPOCH_LENGTH + constants::EPOCH_LENGTH); i++)
	{
		BOOST_ASSERT(cache_t::get_seedhash(i).to_hex() == second_hash);
	}
}

// test that light hashes and full hashes produce the same values
BOOST_AUTO_TEST_CASE(light_hash_vs_full_hash_comparison)
{
	using namespace std;
	using namespace egihash;

	if (!boost::filesystem::exists( "data/egihash.dag" ))
	{
		egihash::dag_t dag(0, dag_progress);
		dag.save("data/egihash.dag");
	}

	dag_t d("data/egihash.dag", dag_progress);
	cache_t c(d.get_cache());

	string rawdata("this is a test string to be hashed");
	h256_t firsthash(rawdata.c_str(), rawdata.size());

	for (size_t i = 0; i < 1000; i++)
	{
		uint64_t nonce = (*reinterpret_cast<uint64_t *>(&firsthash.b[0])) ^ (*reinterpret_cast<uint64_t *>(&firsthash.b[16]));
		firsthash = h256_t(&firsthash.b[0], firsthash.hash_size);
		auto const lighthash = light::hash(c, firsthash, nonce);
		auto const fullhash = full::hash(d, firsthash, nonce);

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

// test loading from the the dag cache as well as unloading
BOOST_AUTO_TEST_CASE(dag_cache)
{
	using namespace std;
	using namespace egihash;

	BOOST_REQUIRE_MESSAGE(boost::filesystem::exists("data/egihash.dag"), "DAG file not generated yet. Please re-run test case.");

	dag_t d1("data/egihash.dag", dag_progress);

	bool success = true;
	auto already_loaded = [&success](::std::size_t /*step*/, ::std::size_t /*max*/, int /*phase*/) -> bool
	{
		// if we have to load, we already failed because this dag should be loaded
		success = false;
		return false;
	};

	// ensure we don't try to load a DAG again when it is already loaded
	dag_t d2("data/egihash.dag", already_loaded);
	try
	{
		BOOST_REQUIRE_MESSAGE(success, "Attempt to re-load already loaded DAG - should be retrieved from DAG cache");
	}
	catch (hash_exception const &)
	{
		// ignored exception - we cancelled loading so we expect this
	}
	BOOST_ASSERT(dag_t::is_loaded(0));
	BOOST_ASSERT(dag_t::get_loaded().size() == 1);
	d1.unload();
	BOOST_ASSERT(!dag_t::is_loaded(0));
	BOOST_ASSERT(dag_t::get_loaded().size() == 0);
	success=false;

	// ensure that after unloading, we would require re-loading this DAG
	auto not_loaded = [&success](::std::size_t /*step*/, ::std::size_t /*max*/, int /*phase*/) -> bool
	{
		success = true;
		return false;
	};
	try
	{
		dag_t d3("data/egihash.dag", not_loaded);
		BOOST_REQUIRE_MESSAGE(success, "Unloaded DAG was not re-loaded correctly");
	}
	catch (hash_exception const &)
	{
		// ignored exception - we cancelled loading so we expect this
	}
	BOOST_ASSERT(!dag_t::is_loaded(0));
	BOOST_ASSERT(dag_t::get_loaded().size() == 0);
	BOOST_ASSERT(success);
}

// test loading from the the cache cache as well as unloading
BOOST_AUTO_TEST_CASE(cache_cache)
{
	using namespace std;
	using namespace egihash;

	cache_t c1(0, dag_progress);

	bool success = true;
	auto already_loaded = [&success](::std::size_t /*step*/, ::std::size_t /*max*/, int /*phase*/) -> bool
	{
		// if we have to load, we already failed because this dag should be loaded
		success = false;
		return false;
	};

	// ensure we don't try to load a cache again when it is already loaded
	cache_t c2(0, already_loaded);
	try
	{
		BOOST_REQUIRE_MESSAGE(success, "Attempt to re-load already loaded cache_t - should be retrieved from cache cache");
	}
	catch (hash_exception const &)
	{
		// ignored exception - we cancelled loading so we expect this
	}
	BOOST_ASSERT(cache_t::is_loaded(0));
	BOOST_ASSERT(cache_t::get_loaded().size() == 1);
	c1.unload();
	BOOST_ASSERT(!cache_t::is_loaded(0));
	BOOST_ASSERT(cache_t::get_loaded().size() == 0);
	success=false;

	// ensure that after unloading, we would require re-loading this DAG
	auto not_loaded = [&success](::std::size_t /*step*/, ::std::size_t /*max*/, int /*phase*/) -> bool
	{
		success = true;
		return false;
	};
	try
	{
		cache_t c3(0, not_loaded);
		BOOST_REQUIRE_MESSAGE(success, "Unloaded DAG was not re-loaded correctly");
	}
	catch (hash_exception const &)
	{
		// ignored exception - we cancelled loading so we expect this
	}
	BOOST_ASSERT(!cache_t::is_loaded(0));
	BOOST_ASSERT(cache_t::get_loaded().size() == 0);
	BOOST_ASSERT(success);
}

BOOST_AUTO_TEST_SUITE_END();
