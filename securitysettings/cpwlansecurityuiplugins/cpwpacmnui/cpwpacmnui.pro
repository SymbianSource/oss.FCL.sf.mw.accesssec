# Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
# All rights reserved.
# This component and the accompanying materials are made available
# under the terms of the License "Eclipse Public License v1.0"
# which accompanies this distribution, and is available
# at the URL "http://www.eclipse.org/legal/epl-v10.html".
# Initial Contributors:
# Nokia Corporation - initial contribution.
# Contributors:
# Description:
# %version: 10 %
TEMPLATE = lib
TARGET = cpwpacmnui
DEPENDPATH += 
INCLUDEPATH += $$MW_LAYER_SYSTEMINCLUDE \
    $$OS_LAYER_SYSTEMINCLUDE \
    ../../inc
    
CONFIG += hb
LIBS += -lcpframework \
    -leapqtplugininfo \
    -leapqtconfiginterface \
    -lconnection_settings_shim

# Input
HEADERS += traces/OstTraceDefinitions.h \
    inc/cpwpacmnui_global.h \
    inc/cpwpacmnui.h
SOURCES += src/cpwpacmnui.cpp

# QMAKE_EXTRA_TARGETS += copyheaders
# directories
#The actual path to be replaced later
DESTDIR = HB_BUILD_DIR/lib
win32:DLLDESTDIR = HB_BUILD_DIR/bin
DEFINES += WPAUI_LIBRARY

defFilePath = ..

symbian:
 { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002DC74
    BLD_INF_RULES.prj_exports += "./rom/cpwpacmnui.iby $$CORE_MW_LAYER_IBY_EXPORT_PATH(cpwpacmnui.iby)"
}

# Temporary solution to fix tracecompiler
# When tracecompiler is fixed, this can be removed
symbian: {
    MMP_RULES += "USERINCLUDE traces"
}

TARGET.CAPABILITY = CAP_GENERAL_DLL
