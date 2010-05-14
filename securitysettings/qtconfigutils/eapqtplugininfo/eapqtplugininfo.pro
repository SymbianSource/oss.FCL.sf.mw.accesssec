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

# %version: 1 %


TEMPLATE            = lib
TARGET              = eapqtplugininfo
TARGET.CAPABILITY   = CAP_GENERAL_DLL
DEFINES             += BUILD_EAP_QT_PLUGIN_INFO_DLL
DEPENDPATH          += . 

# Store generated files to their own directories
MOC_DIR     = _moc
RCC_DIR     = _rcc
OBJECTS_DIR = _objects

# hb config needed when hb classes are used
CONFIG += hb

INCLUDEPATH += \
	../../inc \
    $$MW_LAYER_SYSTEMINCLUDE
    
HEADERS += 

SOURCES += \
    src/eapqtplugininfo.cpp \
    src/eapqtpluginhandle.cpp
    
defFilePath = ..

symbian { 
    # no Symbian only headers
    HEADERS += 
    
    # no Symbian only sources
    SOURCES += 
    
    # add needed Symbian libs here
    LIBS +=
    
    TARGET.UID3 = 0x2002C2FD
    TARGET.EPOCALLOWDLLDATA = 1
    
    TARGET.CAPABILITY = CAP_GENERAL_DLL
    
    # exports not frozen yet
    # MMP_RULES += EXPORTUNFROZEN
    BLD_INF_RULES.prj_exports += \
        "$${LITERAL_HASH}include <platform_paths.hrh>"
        
    BLD_INF_RULES.prj_exports += \ 
  		"rom/eapqtplugininfo.iby CORE_MW_LAYER_IBY_EXPORT_PATH(eapqtplugininfo.iby)"        
}