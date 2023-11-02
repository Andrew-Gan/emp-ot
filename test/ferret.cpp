#include "emp-ot/emp-ot.h"
#include "test/test.h"
using namespace std;

int port, party;
const static int threads = 2;

void test_ferret(int party, NetIO *ios[threads], int64_t num_ot, bool malicious, int gpu_mode) {
	auto start = clock_start();
	FerretCOT<NetIO> * ferretcot = new FerretCOT<NetIO>(party, threads, ios, malicious, true, ferret_b13, "", gpu_mode);
	double timeused = time_from(start);
	std::cout << party << "\tsetup\t" << timeused/1000 << "ms" << std::endl;

	// RCOT
	// The RCOTs will be generated at internal memory, and copied to user buffer
	// int64_t num = 1 << num_ot;
	// cout <<"Active FERRET RCOT\t"<<double(num)/test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, num, false)*1e6<<" OTps"<<endl;

	// RCOT inplace
	// The RCOTs will be generated at user buffer
	// Get the buffer size needed by calling byte_memory_need_inplace()
	uint64_t batch_size = ferretcot->ot_limit;
	cout <<"Active FERRET RCOT inplace\t"<<double(batch_size)/test_rcot<FerretCOT<NetIO>>(ferretcot, ios[0], party, batch_size, true)*1e6<<" OTps"<<endl;
	delete ferretcot;
}

int main(int argc, char** argv) {
	gpu_init();

	parse_party_and_port(argv, &party, &port);
	NetIO* ios[threads];
	for(int i = 0; i < threads; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port+i);

	int64_t length = 24;
	if (argc > 3)
		length = atoi(argv[3]);
	if(length > 30) {
		cout <<"Large test size! comment me if you want to run this size\n";
		exit(1);
	}

	cout << "Semi-Honst" << endl;
	cout << "CPU Test" << endl;
	test_ferret(party, ios, length, false, 0);
	cout << "GPU Test" << endl;
	test_ferret(party, ios, length, false, 1);

	cout << endl << "Semi-Honst" << endl;
	cout << "CPU Test" << endl;
	test_ferret(party, ios, length, true, 0);
	cout << "GPU Test" << endl;
	test_ferret(party, ios, length, true, 1);

	for(int i = 0; i < threads; ++i)
		delete ios[i];
}
