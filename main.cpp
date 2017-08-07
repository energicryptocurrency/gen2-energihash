#include "egihash.h"

int main(int argc, char * argv[])
{
	(void)argc;
	(void)argv;
	if (egihash::test_function()) return 0;
	return 1;
}
