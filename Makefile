DEBUG=0
CC=gcc
ONEFILE_CFLAGS=-std=c++14 \
			   -Wall \
			   -fno-rtti \
			   -fno-exceptions
ifeq ($(DEBUG),1)
ONEFILE_CFLAGS+=-DDEBUG=1 -O0 -ggdb3
else
ONEFILE_CFLAGS+=-DDEBUG=0 -O3 -finline-small-functions
endif
CFLAGS=-c $(ONEFILE_CFLAGS)
LFLAGS=

wizard: wizard.cxx
	$(CC) $(ONEFILE_CFLAGS) $^ -o $@
	@if [ "$(DEBUG)" == "0" ]; then \
		strip wizard -s -R .comment -R .note.gnu.build-id -R .note.ABI-tag; \
	fi

.PHONY: clean
clean:
	@rm -vf wizard
