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
#	EAP method configuration QT interface
#

# %version: 28 %


TEMPLATE            = lib
TARGET              = eapqtconfiginterface

# to export the public class
DEFINES             += BUILD_EAP_QT_CONFIG_INTERFACE_DLL
DEPENDPATH          += . 

# for using hb classes
CONFIG += hb

# translations
TRANSLATIONS += cpeapuiplugins.ts \
				eapprompts.ts

# Storage for generated files
MOC_DIR     = _build
RCC_DIR     = _build
OBJECTS_DIR = _build

INCLUDEPATH += \
    ../../inc \
    ../../../inc/pacstore_inc
   
HEADERS += \
    inc/eapqtcertificateinfo_p.h \
    inc/eapqtconfig_p.h \
    inc/eapqtconfiginterface_p.h \
    inc/eapqtpacstoreconfig_p.h \
    inc/eapqtvalidatorpacstorepassword.h \
    inc/eapqtvalidatorpacstorepasswordconfirm.h \
    inc/eapqtvalidatorpassword.h \
    inc/eapqtvalidatorrealm.h \
    inc/eapqtvalidatorusername.h
    
SOURCES += \
    src/eapqtconfiginterface.cpp \
    src/eapqtconfiginterface_p.cpp \
    src/eapqtcertificateinfo.cpp \
    src/eapqtcertificateinfo_p.cpp \
    src/eapqtconfig.cpp \
    src/eapqtconfig_p.cpp \
    src/eapqtvalidatorpassword.cpp \
    src/eapqtvalidatorrealm.cpp \
    src/eapqtvalidatorusername.cpp \
    src/eapqtpacstoreconfig.cpp \
    src/eapqtpacstoreconfig_p.cpp \
    src/eapqtvalidatorpacstorepassword.cpp \
    src/eapqtvalidatorpacstorepasswordconfirm.cpp
    
# qt libs
LIBS += \
    -leapqtplugininfo

mmpRuleDeffile = \
    "$${LITERAL_HASH}ifdef WINSCW" \
    "DEFFILE ./bwins/eapqtconfiginterface.def" \
    "$${LITERAL_HASH}else" \
    "DEFFILE ./eabi/eapqtconfiginterface.def" \
    "$${LITERAL_HASH}endif"

symbian { 
    # symbian libs
    LIBS += \
        -leapsymbiantools \
        -leaptools \
        -lecom \
        -lcmmanager
    
    TARGET.UID3 = 0x2002C2FC
    TARGET.EPOCALLOWDLLDATA = 1
    
    MMP_RULES += mmpRuleDeffile

    TARGET.CAPABILITY = CAP_GENERAL_DLL
                    
    BLD_INF_RULES.prj_exports += \ 
  		"rom/eapqtconfiginterface.iby CORE_MW_LAYER_IBY_EXPORT_PATH(eapqtconfiginterface.iby)"

    BLD_INF_RULES.prj_exports += \ 
  		"rom/eapqtconfiginterface_resources.iby LANGUAGE_APP_LAYER_IBY_EXPORT_PATH(eapqtconfiginterface_resources.iby)"
}
