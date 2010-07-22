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
#   Project info file for Control Panel SIM/AKA settings plugin. 
#

# %version:  11 %


TEMPLATE = lib
TARGET = cpeapsimakaui

INCLUDEPATH += \
    ../../inc

CONFIG += hb \
    plugin

LIBS += -lcpframework \
        -leapqtconfiginterface \
        -leapqtplugininfo 

MOC_DIR    = _build
RCC_DIR    = _build
OBJECTS_DIR= _build


# Sources
HEADERS +=  \
    ../inc/eapuidefs.h \
    inc/cpeapsimakaui.h \
    inc/cpeapsimakaplugin.h   

SOURCES += \ 
    src/cpeapsimakaui.cpp \
    src/cpeapsimakaplugin.cpp

symbian: { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C2F9  
    TARGET.CAPABILITY = CAP_GENERAL_DLL

    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/eapsecurity
    qtplugins.sources += qmakepluginstubs/cpeapsimakaui.qtplugin

    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
    
    BLD_INF_RULES.prj_exports += \ 
  		"rom/cpeapsimakaui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpeapsimakaui.iby)"
}

plugin.sources += cpeapsimakaui.dll
plugin.path = /resource/qt/plugins/controlpanel/eapsecurity
DEPLOYMENT += plugin
