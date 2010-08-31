#
# Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
#   Common UI implementation for WPA/WPA2, 802.1x and 
#   WPA2 WLAN security modes

# %version: tr1cfwln#17 %

TEMPLATE = lib
TARGET = cpwpacmnui

DEFINES += WPAUI_LIBRARY
DEPENDPATH += 

INCLUDEPATH += \
    ../inc
    
CONFIG += hb

LIBS += \
    -lcpframework \
    -leapqtplugininfo \
    -leapqtconfiginterface \
    -lconnection_settings_shim
    
MOC_DIR     = _build
RCC_DIR     = _build
OBJECTS_DIR = _build

# Input
HEADERS += \
    traces/OstTraceDefinitions.h \
    inc/cpwpacmnui_p.h \
    inc/wpakeyvalidator.h \
    inc/cpwpacmneapui.h \
    ../inc/cpwpacmnui_global.h \
    ../inc/cpwpacmnui.h
  
SOURCES += \ 
    src/cpwpacmnui.cpp \
    src/cpwpacmnui_p.cpp \
    src/wpakeyvalidator.cpp \
    src/cpwpacmneapui.cpp

defFilePath = ..

symbian:
{ 
    TARGET.CAPABILITY = CAP_GENERAL_DLL
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002DC74
    
    BLD_INF_RULES.prj_exports += \ 
      "./rom/cpwpacmnui.iby $$CORE_MW_LAYER_IBY_EXPORT_PATH(cpwpacmnui.iby)"
}

symbian:
{
    MMP_RULES += "USERINCLUDE traces"
}
