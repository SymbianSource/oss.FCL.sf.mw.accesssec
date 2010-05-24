#
# Copyright (c) 2009 Nokia Corporation and/or its subsidiary(-ies).
# All rights reserved.
# This component and the accompanying materials are made available
# under the terms of "Eclipse Public License v1.0"
# which accompanies this distribution, and is available
# at the URL "http://www.eclipse.org/legal/epl-v10.html".
#
# Initial Contributors:
# Nokia Corporation - initial contribution.
#
# Contributors:
#
# Description:
# This is the build file for testing EAP Configuration Interface.

#
# %version: 5 %
#

CONFIG += debug include_ui_tests

QT += testlib
QT -= gui

TEMPLATE = app
TARGET = t_qtconfigutils

DEPENDPATH += .
MOC_DIR = _moc
INCLUDEPATH += $$MW_LAYER_SYSTEMINCLUDE \
               $$OS_LAYER_SYSTEMINCLUDE

# use this to include ui related cases in the tests
include_ui_tests: {
	message(*** Build with UI tests. Cannot use textshell emulator.)
	CONFIG  += hb
	DEFINES += INCLUDE_UI_CASES
}

HEADERS += src/testqtconfigutils.h
SOURCES += src/testqtconfigutils.cpp

LIBS += \
    -leapqtplugininfo \
    -leapqtconfiginterface \
    -lconnection_settings_shim
    
symbian: {
	TARGET.CAPABILITY = ALL -TCB 
}

coverage_test: {
	message(*** Coverage test mode build - no OST traces.)
	#NO_OST_TRACES flag is set
}
else {
	message(*** Normal Symbian-mode build.)
}