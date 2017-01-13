TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CFLAGS += -Wformat -Wformat-y2k -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -Wformat=2
QMAKE_CFLAGS += -Wall -Wextra -pedantic

HEADERS += \
    src/ipv4.h \
    src/parser.h \
    src/udp.h \
    src/utils.h \
    src/ethernet.h

SOURCES += \
    src/ipv4.c \
    src/main.c \
    src/parser.c \
    src/udp.c \
    src/utils.c \
    src/ethernet.c

