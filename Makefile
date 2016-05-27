all:dnsinject dnsdetect

dnsinject: dnsinject.c Utils.c
	gcc -o dnsinject dnsinject.c Utils.c -lpcap

dnsdetect: dnsdetect.c Util_detection.c
	gcc -o dnsdetect dnsdetect.c Util_detection.c -lpcap

clean: 
	rm -rf dnsinject dnsdetect
