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
# Control Panel QT UIs for WLAN security settings configuration
#
# %version: tr1cfwln#4.1.1 %

TEMPLATE = subdirs

SUBDIRS  += \
		cpwepui \
		cpwpaui \
		cpwpa2ui \
		cpwpacmnui
		

CONFIG += ordered