all: 
	gcc -o miniVPNclient miniVPNclient.c -lssl -lcrypto -lcrypt -lpthread
	gcc -std=gnu11 -o miniVPNserver miniVPNserver.c -lssl -lcrypto -lcrypt -lpthread
	sudo docker cp ../miniVPN HostU0:/
	sudo docker cp ../miniVPN HostU1:/

clean: 
	rm -f miniVPNclient miniVPNserver 
	rm -f *~

