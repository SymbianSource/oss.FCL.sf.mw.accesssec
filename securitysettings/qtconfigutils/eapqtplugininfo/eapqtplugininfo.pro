#
# Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
# All rights reserved.
# This component and the accompanying materials are made available
# under the terms of the License "Eclipse Public License v1.0"
# which accompanies this distribution, and is available
# at the URL "http://www.eclipse.org/legal/epl-v10.html".
#
# Initial Contributors:
# Nokia Corporation - initial contribution.
#
# Contributors:
#
# Description: 
#   QT EAP plugin information handling component
#

# %version: 9 %


TEMPLATE            = lib
TARGET              = eapqtplugininfo

DEFINES             += BUILD_EAP_QT_PLUGIN_INFO_DLL
DEPENDPATH          += . 

# Storage for generated files
MOC_DIR     = _build
RCC_DIR     = _build
OBJECTS_DIR = _build

# hb config
CONFIG += hb

# path to def files
defFilePath = .

INCLUDEPATH +=
    
HEADERS += inc

SOURCES += \
    src/eapqtplugininfo.cpp \
    src/eapqtplugininfo_p.cpp \
    src/eapqtexpandedeaptype.cpp \
    src/eapqtexpandedeaptype_p.cpp \
    src/eapqtpluginhandle.cpp \
    src/eapqtpluginhandle_p.cpp

symbian { 
    
    # symbian libs
    LIBS += \
        -leapsymbiantools \
        -leaptools \
        -leaptrace
    
    TARGET.UID3 = 0x2002C2FD
    TARGET.EPOCALLOWDLLDATA = 1
    
    TARGET.CAPABILITY = CAP_GENERAL_DLL
    
    # exports not frozen yet
    MMP_RULES += EXPORTUNFROZEN
        
    BLD_INF_RULES.prj_exports += \ 
  		"rom/eapqtplugininfo.iby CORE_MW_LAYER_IBY_EXPORT_PATH(eapqtplugininfo.iby)"        
}
