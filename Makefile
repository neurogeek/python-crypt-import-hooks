RM := rm -rf

SRCs_conv=src/CryptImpHook_Conv.c src/Cipher.c
SRCs_crypto=src/CryptImpHook.c src/Cipher.c
OBJS_crypto=CryptImpHook.o Cipher.o
PYTHON_CFLAGS=$(shell python-config --includes)
PYTHON_LDFLAGS=$(shell python-config --libs)
PYTHON_LIBDIR=-L$(shell python-config --prefix)/lib

# All Target
all: CryptImpHook.so CryptConv
	@echo ' '
	@echo ' '
	@echo '********* Please, run "make test" now ***********'
	@echo ' '
	@echo ' '

CryptConv: $(SRCs_conv)
	@echo 'Compiling CryptImpHook'
	$(CC) -o "dist/CryptConv" $(SRCs_conv) 

CryptImpHook.o: src/CryptImpHook.c
	@echo 'Compiling CryptImpHook'
	$(CC) -fPIC -c -I./src/ $(PYTHON_CFLAGS) src/CryptImpHook.c

Cipher.o: src/Cipher.c
	@echo 'Compiling DEC'
	$(CC) -fPIC -c -I./src/ $(PYTHON_CFLAGS) src/Cipher.c

# Tool invocations
CryptImpHook.so: $(OBJS_crypto)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	-@mkdir dist
	$(CC) -g -O2 -fPIC -shared -o "dist/CryptImpHook.so" $(PYTHON_LIBDIR) $(PYTHON_LDFLAGS) $(OBJS_crypto)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS_crypto) dist
	-$(RM) EncModule.pye
	-$(RM) docs
	-@echo ' '

docs:
	-doxygen

test:
	python runtests.py

.PHONY: all clean docs test
.SECONDARY:
