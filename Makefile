all: enc_server enc_client dec_server dec_client keygen

enc_server:
	gcc -o enc_server enc_server.c

enc_client:
	gcc -o enc_client enc_client.c

dec_server:
	gcc -o dec_server dec_server.c

dec_client:
	gcc -o dec_client dec_client.c

keygen:
	gcc -o keygen keygen.c

.PHONY: kill-enc kill-dec

clean:
	rm -f enc_server enc_client dec_server dec_client keygen
	@pkill -f './enc_server' || echo "No process named ./enc_server found"
	@pkill -f './dec_server' || echo "No process named ./dec_server found"
