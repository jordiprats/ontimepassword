

pam:
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 pam_ontimepassword.c
	gcc $(LDFLAGS) -o pam_ontimepassword.so -s -lpam -lcrypt --shared pam_ontimepassword.o

clean:
	rm pam_ontimepassword.so pam_ontimepassword.o