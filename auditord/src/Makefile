
a:= 234

files := $(shell echo *.c)

ERROR_001=demo


#auditord.d : *.c
#	@set -e; rm -f $@; \
#	$(CC) -MM $(CPPFLAGS) $< > $@.$$$$; \
#	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
#	rm -f $@.$$$$


%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

auditord.o:auditord.c
