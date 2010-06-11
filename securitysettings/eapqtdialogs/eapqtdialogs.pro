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
# Description: EAP Dialog build file
#
#

TEMPLATE = lib
TARGET = eapdialogplugin
CONFIG += hb plugin

# directories
INCLUDEPATH += .
DEPENDPATH += .
DESTDIR = $${HB_BUILD_DIR}/plugins/devicedialogs

# directories for generated files
MOC_DIR     = _moc
RCC_DIR     = _rcc
OBJECTS_DIR = _obj
HEADERS += inc/eapdialogplugin.h \
           inc/eapusernamepwddialog.h  \ 
           traces/OstTraceDefinitions.h

SOURCES += src/eapdialogplugin.cpp \
           src/eapusernamepwddialog.cpp

symbian: {
    TARGET.EPOCALLOWDLLDATA = 1
    TARGET.CAPABILITY = CAP_GENERAL_DLL
    TARGET.UID3 = 0x2002E6F2
    BLD_INF_RULES.prj_exports += "rom/eapdialogplugin.iby CORE_APP_LAYER_IBY_EXPORT_PATH(eapdialogplugin.iby)"
    BLD_INF_RULES.prj_exports += "rom/eapdialogplugin_resources.iby LANGUAGE_APP_LAYER_IBY_EXPORT_PATH(eapdialogplugin_resources.iby)"

    pluginstub.sources = eapdialogplugin.dll
    pluginstub.path = /resource/plugins/devicedialogs
    DEPLOYMENT += pluginstub
}
TRANSLATIONS = cellularpromptdialog.ts

LIBS  += -leapqtconfiginterface -leapqtplugininfo

# RESOURCES += res/eapdialog.qrc