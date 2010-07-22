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
#	Project file for accesssec_plat Qt exports
#

# %version: 2 %

TEMPLATE = subdirs

include(eap_qt_configuration_api/eap_qt_configuration_api.pri)

for(filename,PLATFORM_HEADERS){
    BLD_INF_RULES.prj_exports *= "$$filename MW_LAYER_PLATFORM_EXPORT_PATH($$basename(filename))"
}
