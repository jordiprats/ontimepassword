
stealth: md5.c pam_ontimepassword.c
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 md5.c 2>/dev/null
	gcc $(CFLAGS) -Wunused -c -fPIC -D_STEALTH_MODE_ -DHAVE_SHADOW -O2 pam_ontimepassword.c
	gcc $(LDFLAGS) -o pam_ontimepassword.so -s -lpam -lcrypt --shared pam_ontimepassword.o md5.o

ontime: md5.c pam_ontimepassword.c
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 md5.c 2>/dev/null
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 pam_ontimepassword.c
	gcc $(LDFLAGS) -o pam_ontimepassword.so -s -lpam -lcrypt --shared pam_ontimepassword.o md5.o

fortune: md5.c pam_ontimepassword.c
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 md5.c 2>/dev/null
	gcc $(CFLAGS) -Wunused -c -fPIC -D_FORTUNE_JORDI_ -DHAVE_SHADOW -O2 pam_ontimepassword.c
	gcc $(LDFLAGS) -o pam_ontimepassword.so -s -lpam -lcrypt --shared pam_ontimepassword.o md5.o

clean:
	rm pam_ontimepassword.so pam_ontimepassword.o

install: pam_ontimepassword.so
	cp pam_ontimepassword.so /lib/security
