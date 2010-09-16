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
#	Control Panel QT UI for TLS ciphersuite configuration in EAP methods
#

# %version: 10 %


TEMPLATE = lib
TARGET = cpeapciphersuiteui

DEFINES += BUILD_CP_EAP_CIPHERSUITE_UI_DLL

CONFIG += hb

LIBS += -lcpframework

MOC_DIR    = _build
RCC_DIR    = _build
OBJECTS_DIR= _build

HEADERS += \
    ../inc/eapuidefs.h \
	inc/cpeapciphersuiteui.h \
	inc/cpeapciphersuiteui_p.h
             
SOURCES += \
	src/cpeapciphersuiteui.cpp \
	src/cpeapciphersuiteui_p.cpp

mmpRuleDeffile = \
    "$${LITERAL_HASH}ifdef WINSCW" \
    "DEFFILE ./bwins/cpeapciphersuiteui.def" \
    "$${LITERAL_HASH}else" \
    "DEFFILE ./eabi/cpeapciphersuiteui.def" \
    "$${LITERAL_HASH}endif"

symbian: {
	TARGET.UID3 = 0x2002C2F8
	TARGET.CAPABILITY = CAP_GENERAL_DLL
	TARGET.EPOCALLOWDLLDATA = 1

    MMP_RULES += mmpRuleDeffile

  	BLD_INF_RULES.prj_exports += \ 
  		"rom/cpeapciphersuiteui.iby CORE_MW_LAYER_IBY_EXPORT_PATH(cpeapciphersuiteui.iby)" \
  		"inc/cpeapciphersuiteui.h    |../inc/cpeapciphersuiteui.h"
  	
}
