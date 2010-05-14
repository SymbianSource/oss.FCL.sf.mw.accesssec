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
# Control Panel QT UI for WPA configuration
# %version: tr1cfwln#7 %
TEMPLATE = lib
TARGET = cpwpaui
DEPENDPATH += 
INCLUDEPATH += $$MW_LAYER_SYSTEMINCLUDE \
    $$OS_LAYER_SYSTEMINCLUDE \
    ../cpwpacmnui/inc \
    ../../inc
    
CONFIG += hb \
    plugin
LIBS += -lcpframework \
    -leapqtplugininfo \
    -lcpwpacmnui \
    -lconnection_settings_shim
MOC_DIR = _moc
RCC_DIR = _rcc
OBJECTS_DIR = _objects

# Input
HEADERS += inc/wpakeyvalidator.h \
    traces/OstTraceDefinitions.h \
    inc/cpwpaui.h
SOURCES += src/wpakeyvalidator.cpp \
    src/cpwpaui.cpp
symbian: { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C301
    LIBS += -leapqtconfiginterface
    BLD_INF_RULES.prj_exports += "rom/cpwpaui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpwpaui.iby)"
}
symbian { 
    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/wlansecurity
    qtplugins.sources += qmakepluginstubs/cpwpaui.qtplugin
    
    # This is for new exporting system coming in garden
    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
}

# temporary not used; waiting for the latest .ts file ; accordingly export will change
# translation file temporarily read as qt resource
# TRANSLATIONS += /resource/qtwlan_en_GB.ts

# Temporary solution to fix tracecompiler
# When tracecompiler is fixed, this can be removed
symbian: {
    MMP_RULES += "USERINCLUDE traces"
}

RESOURCES += resources/resource.qrc

TARGET.CAPABILITY = CAP_GENERAL_DLL
dynamiclibrary.sources = cpwpacmnui.dll
dynamiclibrary.path = /sys/bin
plugin.sources += cpwpaui.dll
plugin.path = /resource/qt/plugins/controlpanel
DEPLOYMENT += plugin \
    dynamiclibrary

