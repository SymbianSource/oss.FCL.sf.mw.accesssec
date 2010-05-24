# Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
# All rights reserved.
# This component and the accompanying materials are made available
# under the terms of the License "Eclipse Public License v1.0"
# which accompanies this distribution, and is available
# at the URL "http://www.eclipse.org/legal/epl-v10.html".
#
# Initial Contributors:
# 	Nokia Corporation - initial contribution.
#
# Contributors:
#
# Description:
# 	Control Panel UI for WPA/WPA2 only Security mode
#
# %version: 15 %
#

TEMPLATE = lib
TARGET = cpwpaui

DEPENDPATH += 

INCLUDEPATH += \ 
	$$MW_LAYER_SYSTEMINCLUDE \
    $$OS_LAYER_SYSTEMINCLUDE \
    ../inc
    
CONFIG += \
	hb \
    plugin
    
LIBS += \
	-lcpframework \
    -lcpwpacmnui \
    -lconnection_settings_shim \
    -leapqtconfiginterface
    
MOC_DIR = _moc
RCC_DIR = _rcc
OBJECTS_DIR = _objects

# Input
HEADERS += \
	traces/OstTraceDefinitions.h \
    inc/cpwpaui.h
    
SOURCES += src/cpwpaui.cpp

symbian: 
{ 
	TARGET.CAPABILITY = CAP_GENERAL_DLL
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C301

    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/wlansecurity
    qtplugins.sources += qmakepluginstubs/cpwpaui.qtplugin
    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
    
    BLD_INF_RULES.prj_exports += \
    	"rom/cpwpaui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpwpaui.iby)"
}

symbian:
{
    MMP_RULES += "USERINCLUDE traces"
}

# common translation file for all plugins
TRANSLATIONS = cpwlansecsettingsplugin.ts

plugin.sources += cpwpaui.dll
plugin.path = /resource/qt/plugins/controlpanel

DEPLOYMENT += plugin

