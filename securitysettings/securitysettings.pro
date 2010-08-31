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
#   Project definition file for accesssec package QT components
#
# %version: 7 %
#

TEMPLATE = subdirs

SUBDIRS += \
  qtconfigutils \
  cpwlansecurityuiplugins \
  cpeapuiplugins \
  eapqtdialogs

CONFIG += ordered
