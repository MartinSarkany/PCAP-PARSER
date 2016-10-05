TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c \
    parser.c \
    utils.c

HEADERS += \
    parser.h \
    utils.h

DISTFILES += \
    header_types.txt

QMAKE_CFLAGS += -Wformat -Wformat-y2k -Wno-format-zero-length -Wformat-nonliteral -Wformat-security -Wformat=2
