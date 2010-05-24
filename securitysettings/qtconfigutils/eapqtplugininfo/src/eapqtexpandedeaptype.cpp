/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of the License "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *   Expanded EAP type QT data structure
 *
 */

/*
 * %version: 12 %
 */

#include "eapqtexpandedeaptype.h"
#include "eapqtexpandedeaptype_p.h"

//----------------------------------------------------------------------------
//              EapQtExpandedEapType                
//----------------------------------------------------------------------------

EapQtExpandedEapType::EapQtExpandedEapType() :
    d_ptr(new EapQtExpandedEapTypePrivate)
{
}

EapQtExpandedEapType::EapQtExpandedEapType(const Type type) :
    d_ptr(new EapQtExpandedEapTypePrivate(type))
{
}

EapQtExpandedEapType::EapQtExpandedEapType(const QByteArray data) :
    d_ptr(new EapQtExpandedEapTypePrivate(data))
{
}

EapQtExpandedEapType::EapQtExpandedEapType(const EapQtExpandedEapType & type) :
    d_ptr(new EapQtExpandedEapTypePrivate)
{
    d_ptr->mData = type.d_ptr->mData;
    d_ptr->mType = type.d_ptr->mType;
}

EapQtExpandedEapType::~EapQtExpandedEapType()
{
    // scoped pointer delete
}

QByteArray EapQtExpandedEapType::eapExpandedData() const
{
    return d_ptr->mData;
}

EapQtExpandedEapType::Type EapQtExpandedEapType::type() const
{
    return d_ptr->mType;
}

bool EapQtExpandedEapType::operator ==(const EapQtExpandedEapType &right_type_value) const
{
    return (d_ptr->mData == right_type_value.d_ptr->mData) && (d_ptr->mType == right_type_value.d_ptr->mType);
}

bool EapQtExpandedEapType::operator !=(const EapQtExpandedEapType &right_type_value) const
{
    return (d_ptr->mData != right_type_value.d_ptr->mData) || (d_ptr->mType != right_type_value.d_ptr->mType);
}

EapQtExpandedEapType& EapQtExpandedEapType::operator=(const EapQtExpandedEapType &type)
{
    // check if assigning to myself
    if (this != &type) {
        d_ptr.reset(new EapQtExpandedEapTypePrivate);
        d_ptr->mData = type.d_ptr->mData;
        d_ptr->mType = type.d_ptr->mType;
    }
    return *this;
}

