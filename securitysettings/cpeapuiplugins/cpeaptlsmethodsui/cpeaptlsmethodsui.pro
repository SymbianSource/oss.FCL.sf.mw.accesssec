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
#	Control Panel QT UI for TLS-based EAP methods configuration
#

# %version: 14 %


TEMPLATE = lib
TARGET = cpeaptlsmethodsui

INCLUDEPATH += \
    ../../inc

CONFIG += hb \
    plugin

LIBS += -lcpframework \
        -leapqtconfiginterface \
        -leapqtplugininfo \
        -lcpeapciphersuiteui

MOC_DIR    = _build
RCC_DIR    = _build
OBJECTS_DIR= _build


# Sources
HEADERS +=  \
    ../inc/eapuidefs.h \
    inc/cpeaptlsmethodsui.h \
    inc/cpeaptlsmethodsplugin.h \
    inc/cpeaptlsmethodsinnereapui.h \
    inc/cpeappacstoreui.h 

SOURCES += \ 
    src/cpeaptlsmethodsui.cpp \
    src/cpeaptlsmethodsplugin.cpp \
    src/cpeaptlsmethodsinnereapui.cpp \
    src/cpeappacstoreui.cpp

symbian: { 
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.UID3 = 0x2002C2FA  
    TARGET.CAPABILITY = CAP_GENERAL_DLL

    deploy.path = c:
    qtplugins.path = /resource/qt/plugins/controlpanel/eapsecurity
    qtplugins.sources += qmakepluginstubs/cpeaptlsmethodsui.qtplugin

    for(qtplugin, qtplugins.sources):BLD_INF_RULES.prj_exports += "./$$qtplugin $$deploy.path$$qtplugins.path/$$basename(qtplugin)"
    
    BLD_INF_RULES.prj_exports += \ 
  		"rom/cpeaptlsmethodsui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpeaptlsmethodsui.iby)"
}

plugin.sources += cpeaptlsmethodsui.dll
plugin.path = /resource/qt/plugins/controlpanel/eapsecurity
DEPLOYMENT += plugin
