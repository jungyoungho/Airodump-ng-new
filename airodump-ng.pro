TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.cpp \
    key.cpp

HEADERS += \
    necessary_header.h \
    key.h \
    value.h \
    sta_key.h \
    sta_value.h
