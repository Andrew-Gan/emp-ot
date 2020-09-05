#include "test/test.h"
using namespace std;

const static int threads = 5;

int main(int argc, char** argv) {
	int length = 1<<24, port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr:"127.0.0.1", port);
	OTNP<NetIO> * np = new OTNP<NetIO>(io);
	cout <<"128 NPOTs:\t"<<test_ot<OTNP<NetIO>>(np, io, party, 128)<<" us"<<endl;
	delete np;
	IKNP<NetIO> * iknp = new IKNP<NetIO>(io);
	cout <<"Passive IKNP OT\t"<<double(length)/test_ot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive IKNP COT\t"<<double(length)/test_cot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Passive IKNP ROT\t"<<double(length)/test_rot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	delete iknp;

	OTCO<NetIO> * co = new OTCO<NetIO>(io);
	cout <<"128 COOTs:\t"<<test_ot<OTCO<NetIO>>(co, io, party, 128)<<" us"<<endl;
	delete co;
	iknp = new IKNP<NetIO>(io, true);
	cout <<"Active IKNP OT\t"<<double(length)/test_ot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active IKNP COT\t"<<double(length)/test_cot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	cout <<"Active IKNP ROT\t"<<double(length)/test_rot<IKNP<NetIO>>(iknp, io, party, length)*1e6<<" OTps"<<endl;
	delete iknp;
	delete io;

	NetIO* ios[threads+1];
	for(int i = 0; i < threads+1; ++i)
		ios[i] = new NetIO(party == ALICE?nullptr:"127.0.0.1",port);
	FerretCOT<NetIO, threads> * ferretcot = new FerretCOT<NetIO, threads>(party, ios, true);
	cout <<"Active VOLE OT\t"<<double(length)/test_ot<FerretCOT<NetIO, threads>>(ferretcot, ios[0], party, length)*1e6<<" OTps"<<endl;
	cout <<"Active VOLE COT\t"<<double(length)/test_cot<FerretCOT<NetIO, threads>>(ferretcot, ios[0], party, length)*1e6<<" OTps"<<endl;
	cout <<"Active VOLE ROT\t"<<double(length)/test_rot<FerretCOT<NetIO, threads>>(ferretcot, ios[0], party, length)*1e6<<" OTps"<<endl;
	delete ferretcot;
	for(int i = 0; i < threads+1; ++i)
		delete ios[i];
}

