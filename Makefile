.PHONY: all clean signAttPeer signAttReq
all:
	make -C ./signAttestRequester all
	make -C ./signAttestPeer all

signAttReq:
	make -C ./signAttestRequester signAttReq

signAttPeer:
	make -C ./signAttestPeer signAttPeer

clean:
	rm -rf ./target
	rm -rf ./keys
