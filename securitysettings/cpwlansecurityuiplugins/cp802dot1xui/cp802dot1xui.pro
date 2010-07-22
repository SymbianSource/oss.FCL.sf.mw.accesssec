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
#   Control Panel plugin for 802.1X WLAN security mode
#
# %version: tr1cfwln#12 %
#

TEMPLATE = lib
TARGET = cp802dot1xui

DEPENDPATH += 

INCLUDEPATH += \
    ../inc
    
CONFIG += \
    hb \
    plugin
    
LIBS += \ 
    -lcpframework \
    -lcpwpacmnui \
    -lconnection_settings_shim \
    -leapqtconfiginterface
    
MOC_DIR     = _build
RCC_DIR     = _build
OBJECTS_DIR = _build

# Input
HEADERS += \
    traces/OstTraceDefinitions.h \
    inc/cp802dot1xui.h
    
SOURCES += src/cp802dot1xui.cpp

symbian: 
{ 
    TARGET.CAPABILITY = CAP_GENERAL_DLL
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002DC72
    
    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/wlansecurity
    qtplugins.sources += qmakepluginstubs/cp802dot1xui.qtplugin
    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
    
    BLD_INF_RULES.prj_exports += \ 
      "rom/cp802dot1xui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cp802dot1xui.iby)"
}

symbian:
{
    MMP_RULES += "USERINCLUDE traces"
}

# common translation file for all plugins
TRANSLATIONS = cpwlansecsettingsplugin.ts

plugin.sources += cp802dot1xui.dll
plugin.path = /resource/qt/plugins/controlpanel

DEPLOYMENT += plugin
