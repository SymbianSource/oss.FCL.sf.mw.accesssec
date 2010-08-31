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
# %version: 13 %
#

TEMPLATE = lib
TARGET = eapdialogplugin
CONFIG += hb plugin

# directories
INCLUDEPATH += .
DEPENDPATH += .
DESTDIR = $${HB_BUILD_DIR}/plugins/devicedialogs

# Temporary solution to fix tracecompiler
# When tracecompiler is fixed, this can be removed
symbian: {
    MMP_RULES += "USERINCLUDE traces"
}

# directories for generated files
MOC_DIR     = _build
RCC_DIR     = _build
OBJECTS_DIR = _build

HEADERS += inc/eapdialogplugin.h \
           inc/eapquerydialog.h \
           inc/eappasswordquerydialog.h \
           inc/eapusernamepwddialog.h  \
           inc/eapfastprovwaitnotedialog.h \
           inc/eapmschapv2pwdexpirednotedialog.h \
           inc/eapmschapv2oldpwddialog.h \
           inc/eapmschapv2newpwddialog.h \
           inc/eapfastprovnotsuccessnotedialog.h \
           inc/eapfastinstallpacquerydialog.h \
           inc/eapfastpacstorepwquerydialog.h \
           inc/eapfastpacfilepwquerydialog.h \
           inc/eapfastcreatemasterkeyquerydialog.h \
           traces/OstTraceDefinitions.h

SOURCES += src/eapdialogplugin.cpp \
           src/eapquerydialog.cpp \
           src/eappasswordquerydialog.cpp \
           src/eapusernamepwddialog.cpp \
           src/eapfastprovwaitnotedialog.cpp \
           src/eapmschapv2oldpwddialog.cpp \
           src/eapmschapv2newpwddialog.cpp \
           src/eapmschapv2pwdexpirednotedialog.cpp \
           src/eapfastprovnotsuccessnotedialog.cpp \
           src/eapfastinstallpacquerydialog.cpp \
           src/eapfastpacstorepwquerydialog.cpp \
           src/eapfastpacfilepwquerydialog.cpp \
           src/eapfastcreatemasterkeyquerydialog.cpp

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

TRANSLATIONS = eapprompts.ts

LIBS  += -leapqtconfiginterface -leapqtplugininfo
