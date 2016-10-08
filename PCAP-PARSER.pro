TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    parser.c \
    utils.c \
    udp.c \
    ipv4.c \
    eth_frame.c

HEADERS += \
    parser.h \
    utils.h \
    udp.h \
    ipv4.h \
    eth_frame.h

DISTFILES += \
    header_types.txt

QMAKE_CFLAGS += -Wformat -Wformat-y2k -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -Wformat=2
