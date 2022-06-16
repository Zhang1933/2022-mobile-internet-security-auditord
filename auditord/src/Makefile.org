# build auditord executable when user executes "make"
ifeq ($(PC_TARGET),linux-atheros)
   TARGET_CFLAGS += -DPC_TARGET_LINUX_ATHEROS
endif


#object = auditord.o soapC.o soapClient.o stdsoap2.o ac_json.o audit_gb_code.o
object = auditord.o 
LIB=-luci -lstdc++ -lubox -lpthread 

auditord: $(object)
	$(CXX) $(LDFLAGS) $(object) $(LIB) -O2 -Wall -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(TARGET_CFLAGS) $(AUDITORD_CFLAGS) $(LIB) -c $< -o $@ 


clean:
	${RM} *.o auditord
