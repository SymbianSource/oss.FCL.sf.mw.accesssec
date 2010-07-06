/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *   EAP plugin information
 *
 */

/*
 * %version: 2 %
 */

// System includes

// User includes
#include "eapqtplugininfo_p.h"

/*!
 *  \class EapQtPluginInfoPrivate
 *  \brief Private implementation of EAP plugin information
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtPluginInfoPrivate::EapQtPluginInfoPrivate(const EapQtPluginHandle& handle,
    const QString &locId, const int orderNumber) :
    mHandle(handle), mLocId(locId), mOrderNumber(orderNumber)
{
}

EapQtPluginInfoPrivate::~EapQtPluginInfoPrivate()
{
}
