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
#   Control Panel plugins for WLAN security settings configuration

# %version: tr1cfwln#12 %


TEMPLATE = subdirs

SUBDIRS += \
    cpwepui \
    cpwpacmnui \
    cpwpaui \
    cpwpa2ui \
    cp802dot1xui

CONFIG += ordered

# export common iby for the translation file
symbian:
{
    BLD_INF_RULES.prj_exports += \
      "rom/cpwlansecurityuiplugins_resources.iby LANGUAGE_APP_LAYER_IBY_EXPORT_PATH(cpwlansecurityuiplugins_resources.iby)"
}