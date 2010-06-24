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
#   Project info file for Control Panel username-password based EAP method
#   settings plugin.  
#

# %version: 13 %


TEMPLATE = lib
TARGET = cpeapuserpasswordui

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
    inc/cpeapuserpasswordui.h \
    inc/cpeapuserpasswordplugin.h

SOURCES += \ 
    src/cpeapuserpasswordui.cpp \
    src/cpeapuserpasswordplugin.cpp

symbian: { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C2FB
    TARGET.CAPABILITY = CAP_GENERAL_DLL
 
    deploy.path = C:
    qtplugins.path = /resource/qt/plugins/controlpanel/eapsecurity
    qtplugins.sources += qmakepluginstubs/cpeapuserpasswordui.qtplugin
    
    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
    
    BLD_INF_RULES.prj_exports += \ 
  		"rom/cpeapuserpasswordui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpeapuserpasswordui.iby)"
}

plugin.sources += cpeapuserpasswordui.dll
plugin.path = /resource/qt/plugins/controlpanel/eapsecurity
DEPLOYMENT += plugin
