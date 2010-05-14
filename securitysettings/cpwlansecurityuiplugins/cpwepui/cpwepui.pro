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
# Control Panel QT UI for WEP configuration
# %version: 8 %
TEMPLATE = lib
TARGET = cpwepui
DEPENDPATH += . \
    ./src
INCLUDEPATH += $$MW_LAYER_SYSTEMINCLUDE \
    $$OS_LAYER_SYSTEMINCLUDE
CONFIG += hb \
    plugin
LIBS += -lcpframework \
    -lconnection_settings_shim
MOC_DIR = _moc
RCC_DIR = _rcc
OBJECTS_DIR = _objects

# Input
HEADERS += inc/wepkeyvalidator.h \
    traces/OstTraceDefinitions.h \
    inc/wlansecuritycontrolpanelwepdefs.h \
    inc/cpwepui.h
SOURCES += src/wepkeyvalidator.cpp \
    src/cpwepui.cpp
symbian: { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C2FF
    BLD_INF_RULES.prj_exports += "rom/cpwepui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpwepui.iby)"
}
symbian { 
    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/wlansecurity
    qtplugins.sources += qmakepluginstubs/cpwepui.qtplugin
    
    # This is for new exporting system coming in garden
    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
}

# Temporary solution to fix tracecompiler
# When tracecompiler is fixed, this can be removed
symbian: {
    MMP_RULES += "USERINCLUDE traces"
}

# temporary not used; waiting for the latest .ts file ; accordingly export will change
# translation file temporarily read as qt resource
# TRANSLATIONS += /resource/qtwlan_en_GB.ts

RESOURCES += resources/resource.qrc


TARGET.CAPABILITY = CAP_GENERAL_DLL
plugin.sources += cpwepui.dll
plugin.path = /resource/qt/plugins/controlpanel
DEPLOYMENT += plugin

